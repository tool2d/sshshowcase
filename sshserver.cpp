/* 
 * ssh2 server
 * 2024/07/03
 */
#include "stdafx.h"
#include <net/sshclient.h>

class sshserver_t
{
public:
	static void hash_update(ssl_t* ssl, const byte* r_data, int r_size)
	{
		ssl->m_sha1context.update((const byte*)r_data, r_size);
	}

	static void hash_update_uint32(ssl_t* ssl, const byte* r_data, int r_size)
	{
		byte buffer[4];
		SET_INT32_BIGENDIAN(r_size, buffer);

		ssl->m_sha1context.update((const byte*)buffer, 4);
		ssl->m_sha1context.update((const byte*)r_data, r_size);
	}

	static void hash_keys(byte* r_out, int r_outlen, rsa4096_t& r_dh_k, int r_dh_keybytesize, byte r_sessionid[20], char X)
	{
		sha1context_t sha1context;
		sha1context.init();

		byte  buffer[4096];
		byte* ptr = buffer;
		ssh_t::set_integer(r_dh_k, r_dh_keybytesize, ptr);
		sha1context.update((const byte*)buffer, ptr-buffer);
		sha1context.update((const byte*)r_sessionid, SHA1_DIGEST_SIZE);
		sha1context.update((const byte*)&X, 1);
		sha1context.update((const byte*)r_sessionid, SHA1_DIGEST_SIZE);

		sha1context.final(r_out);
		sha1context.init();

		if (r_outlen > SHA1_DIGEST_SIZE)
		{
			sha1context.update((const byte*)buffer, ptr-buffer);
			sha1context.update((const byte*)r_sessionid, SHA1_DIGEST_SIZE);
			sha1context.update(r_out, SHA1_DIGEST_SIZE);
			sha1context.final(r_out+SHA1_DIGEST_SIZE);
		}
	}

	static void process(content_t* r_content)
	{
		string state = r_content->m_usernode.pair["state"];

		ssh2object_t* obj = (ssh2object_t*)r_content->m_usernode.coreobject;
		if (obj == 0)
		{
			obj = new ssh2object_t;
			obj->m_ssl.m_serverside = true;

			r_content->m_usernode.coreobject = obj;
		}

		ssl_t* ssl = &obj->m_ssl;

		string sendstr;

		if (state == "")
		{
			obj->m_versionsvr = "SSH-2.0-OpenSSH_6.6p1 Ubuntu-2ubuntu1";
			sendstr.format("%s\r\n", (const char*)obj->m_versionsvr);
			network_t::sendstring(r_content, sendstr);

//			string remoteip = r_httplisten->getip(r_content);
//			logout("[SSH IP] %s\n", (const char*)remoteip);

			r_content->m_usernode.pair["state"] = "WAIT_SSHVERSION";
			return;
		}

		// avoid flood attack
		if (r_content->m_recvstream.size())
		{
			if (state == "RECV_BODY")
			{
				if (r_content->m_recvstream.size() > 1024*1024*20) // 20M
				{
					network_t::send_fin(r_content);
					r_content->m_recvstream.reset();
					return;
				}
			}
			else
			{
				if (r_content->m_recvstream.size() > 1024*1024*1) // 1M
				{
					network_t::send_fin(r_content);
					r_content->m_recvstream.reset();
					return;
				}
			}
		}

		stream_t  rawstream;
		stream_t* datastream = &r_content->m_recvstream;

		stream_t sftp_stream;

		if (datastream->size())
		if (datastream->size() >= 2)
		{
			if (state == "WAIT_SSHVERSION")
			{
				int findid = stream_t::find(*datastream, "\r\n");
				if (findid != -1)
				{
					int   memsize = 0;
					byte* memdata = datastream->fetch(memsize);

					string str;
					str.copymemory(memdata, findid);

					obj->m_versioncli = str;

					logout("[cli] %s\n", (const char*)str);
					r_content->m_usernode.pair["state"] = "WAIT_KEY_EXCHANGE";

					int remainsize = memsize-findid-2;
					if (remainsize > 0)
					{
						datastream->append(memdata+findid+2, remainsize);
					}

					SAFE_DELETE_ARRAY(memdata);
				}
			}

			if (state == "WAIT_DECRYPT_DATA")
			if (datastream->size() >= 16)
			{
				byte blockdata[16];

				aeskey_t aeskey = ssl->m_decrypt.aeskey;
				aes_t::cbc_decrypt(&aeskey, datastream->begin(0), blockdata, 16);

				int   packlen = 4 + GET_INT32_BIGENDIAN(blockdata);
				while (datastream->size() >= packlen + 20)
				{
					int   memsize = 0;
					byte* memdata = datastream->fetch(memsize);

					SET_INT32_BIGENDIAN(obj->m_in_sequenceid, blockdata);
					obj->m_hmac_in.Update(blockdata, 4);

					int offset = 0;
					while(packlen-offset >= 16)
					{
						aes_t::cbc_decrypt(&ssl->m_decrypt.aeskey, memdata+offset, blockdata, 16);
						offset += 16;

						rawstream.append(blockdata, 16);
						obj->m_hmac_in.Update(blockdata, 16);
					}

					byte* macptr = memdata+offset;
					byte  macbuffer[20];
					obj->m_hmac_in.Final(macbuffer);

					ASSERTIF(macptr[0] != macbuffer[0]);

					offset += 20; // skip mac

					int remainsize = memsize-offset;
					if (remainsize > 0)
					{
						datastream->append(memdata+offset, remainsize);
					}

					delete[] memdata;

					if (datastream->size() >= 16)
					{
						aeskey = ssl->m_decrypt.aeskey;
						aes_t::cbc_decrypt(&aeskey, datastream->begin(0), blockdata, 16);
						packlen = 4 + GET_INT32_BIGENDIAN(blockdata);
					}

					obj->m_in_sequenceid++;
				}

				datastream = &rawstream;
			}

			if (state == "WAIT_KEY_EXCHANGE" || state == "WAIT_DECRYPT_DATA")
			if (datastream->size() >= 4)
			{
				const byte* packptr = datastream->begin(0);
				int         packlen = GET_INT32_BIGENDIAN(packptr);

				while (datastream->size() >= 4+packlen)
				{
					int   memsize = 0;
					byte* memdata = datastream->fetch(memsize);

					byte* ptr2 = memdata;
					int   msgtotal        = GET_INT32_BIGENDIAN(ptr2); ptr2+=4;
					int   msgpadding_size = *ptr2; ptr2++;
					byte* payload_ptr     = ptr2;
					int   payload_size    = msgtotal-1-msgpadding_size;
					int   msgtype         = *ptr2; ptr2++;

					if (state == "WAIT_KEY_EXCHANGE") obj->m_in_sequenceid++;

					if (msgpadding_size < 4 || (msgtotal % 4) != 0)
					{
						network_t::send_fin(r_content);
					}

					byte  sendbuff[8192];
					int   sendsize = 0;

					if (msgtype == SSH2_MSG_KEXINIT)
					{
						byte  random_cookie[16];
						CopyMemory(random_cookie, ptr2, 16); ptr2 += 16;

						string kex_algorithms             = ssh_t::get_intstring(ptr2);
						string server_host_key_algorithms = ssh_t::get_intstring(ptr2);

						string encryption_algorithms_client_to_server = ssh_t::get_intstring(ptr2);
						string encryption_algorithms_server_to_client = ssh_t::get_intstring(ptr2);

						string mac_algorithms_client_to_server = ssh_t::get_intstring(ptr2);
						string mac_algorithms_server_to_client = ssh_t::get_intstring(ptr2);

						string compression_algorithms_client_to_server = ssh_t::get_intstring(ptr2);
						string compression_algorithms_server_to_client = ssh_t::get_intstring(ptr2);

						string languages_client_to_server = ssh_t::get_intstring(ptr2);
						string languages_server_to_client = ssh_t::get_intstring(ptr2);

						bool   first_kex_packet_follows   = ssh_t::get_boolean(ptr2);
						uint   extension                  = ssh_t::get_uint32(ptr2);

						// 4+1+padding is a multiple of the cipher block size or 8
						ptr2 += msgpadding_size;

						int    calculate_total = ptr2 - memdata;
						ASSERTIF(calculate_total != msgtotal+4);

						// -------------
						byte* ptr = sendbuff;
						ptr += 4; // skip size
						ptr += 1; // skip padding size
						*ptr = SSH2_MSG_KEXINIT; ptr++;

						randomBlock(ptr, 16);
						ptr += 16; // random cookie

						ssh_t::set_intstring("diffie-hellman-group1-sha1", ptr);
						ssh_t::set_intstring("ssh-rsa", ptr);
						ssh_t::set_intstring("aes256-cbc", ptr);
						ssh_t::set_intstring("aes256-cbc", ptr);
						ssh_t::set_intstring("hmac-sha1", ptr);
						ssh_t::set_intstring("hmac-sha1", ptr);
						ssh_t::set_intstring("none", ptr);
						ssh_t::set_intstring("none", ptr);
						ssh_t::set_intstring("", ptr);
						ssh_t::set_intstring("", ptr);

						ssh_t::set_boolean(false, ptr);
						ssh_t::set_uint32(0, ptr);

						sendsize = ptr-sendbuff;

						// ----------------
						ssl->m_sha1context.init();
						hash_update_uint32(ssl, (const byte*)obj->m_versioncli, obj->m_versioncli.size());
						hash_update_uint32(ssl, (const byte*)obj->m_versionsvr, obj->m_versionsvr.size());
						hash_update_uint32(ssl, payload_ptr, payload_size);
						hash_update_uint32(ssl, sendbuff+4+1, (sendsize-4)-1);
					}

					if (msgtype == SSH2_MSG_KEXDH_INIT)
					{
						ssl->m_DH_pubkey = ssh_t::get_integer(ptr2);

rsakey_t prikey;
rsakey_t pubkey;

prikey.generatePrivateKey(0, 1024);
pubkey.setPublicKey(prikey.m_modulus, 1024, prikey.m_e);

						// -------------
						byte* ptr = sendbuff;
						ptr += 4; // skip size
						ptr += 1; // skip padding size
						*ptr = SSH2_MSG_KEXDH_REPLY; ptr++;

						ssl->m_DH_keysize = 128*8; // 1024

						// 1. 生成DH私钥和公钥

						// diffie-hellman-group1-sha1 value for p
						const byte dh_p_group1[]= { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
													0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
													0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,	0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
													0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,	0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
													0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,	0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

						ssl->m_DH_P.from_bytearray(dh_p_group1, sizeof(dh_p_group1));
						ssl->m_DH_G = "2";
						
						// 1.1 create private key
						randomBlock((byte*)ssl->m_DH_prikey.m_data, ssl->m_DH_keysize/8-2); // should small than P, so -2

						// 1.2 send pubkey to server (pubkey = G ^ prikey mod P)
						rsa4096_t dh_pubKey = rsamath_t::modpow(ssl->m_DH_G, ssl->m_DH_P, ssl->m_DH_prikey, ssl->m_DH_keysize);

						// 1.3. compute shared secret as premastersecret
						rsa4096_t share = rsamath_t::modpow(ssl->m_DH_pubkey, ssl->m_DH_P, ssl->m_DH_prikey, ssl->m_DH_keysize);

						// -------------
						// 2.1 写入rsa pubkey
						ssh_t::set_rsa_pubkey(&pubkey, ptr);

						// 2.2 写入DH pubkey(DH_F)
						ssh_t::set_integer(dh_pubKey, ssl->m_DH_keysize/8, ptr);

						// 2.3 生成hash, 并用RSA签名
						{
							byte  hashbuf[4096];
							byte* hashptr = hashbuf;

							ssh_t::set_rsa_pubkey(&pubkey, hashptr);

							// e, exchange value sent by the client
							ssh_t::set_integer(ssl->m_DH_pubkey, ssl->m_DH_keysize/8, hashptr);

							// f, exchange value sent by the server
							ssh_t::set_integer(dh_pubKey, ssl->m_DH_keysize/8, hashptr);

							// K, the shared secret
							ssh_t::set_integer(share, ssl->m_DH_keysize/8, hashptr);

							hash_update(ssl, hashbuf, hashptr-hashbuf);

							byte digest[20];
							int  digestsize = SHA1_DIGEST_SIZE;
							ssl->m_sha1context.final(digest);

							CopyMemory(obj->m_session_id, digest, SHA1_DIGEST_SIZE);

							// sha1 again
							sha1context_t sha1context;
							sha1context.init();
							sha1context.update(digest, SHA1_DIGEST_SIZE);
							sha1context.final(digest);

							// calculate the signature
							byte encode_digest[64];
							int  encode_digestsize = asn_t::EncodeSignature(digest, digestsize, encode_digest);

							rsa4096_t C;
							bool ret1 = rsa_t::ssl_sign(&prikey, encode_digest, encode_digestsize, C);

							ssh_t::set_rsa_sign(C, prikey.getBitSize()/8, ptr);
						}

						sendsize = ptr-sendbuff;

						// -----
						byte C2S_key[64];
						byte C2S_IV[64];
						byte C2S_MAC[64];

						byte S2C_key[64];
						byte S2C_IV[64];
						byte S2C_MAC[64];

						hash_keys(C2S_IV,  SHA1_DIGEST_SIZE, share, ssl->m_DH_keysize/8, obj->m_session_id, 'A');
						hash_keys(S2C_IV,  SHA1_DIGEST_SIZE, share, ssl->m_DH_keysize/8, obj->m_session_id, 'B');
						hash_keys(C2S_key, 32, share, ssl->m_DH_keysize/8, obj->m_session_id, 'C');
						hash_keys(S2C_key, 32, share, ssl->m_DH_keysize/8, obj->m_session_id, 'D');

						hash_keys(C2S_MAC, 32, share, ssl->m_DH_keysize/8, obj->m_session_id, 'E');
						hash_keys(S2C_MAC, 32, share, ssl->m_DH_keysize/8, obj->m_session_id, 'F');

						aes_t::set_encrypt_key(&ssl->m_encrypt.aeskey, S2C_key, 32, S2C_IV);
						aes_t::set_decrypt_key(&ssl->m_decrypt.aeskey, C2S_key, 32, C2S_IV);

						obj->m_hmac_in.SetKey( SHA1_MAC, C2S_MAC, 20);
						obj->m_hmac_out.SetKey(SHA1_MAC, S2C_MAC, 20);
					}

					if (msgtype == SSH2_MSG_NEWKEYS)
					{
						// -------------
						byte* ptr = sendbuff;
						ptr += 4; // skip size
						ptr += 1; // skip padding size
						*ptr = SSH2_MSG_NEWKEYS; ptr++;

						sendsize = ptr-sendbuff;

						r_content->m_usernode.pair["state"] = "WAIT_DECRYPT_DATA";
					}

					if (msgtype == SSH2_CMSG_EOF || msgtype == SSH2_MSG_CHANNEL_EOF || msgtype == SSH2_MSG_CHANNEL_CLOSE)
					{
						network_t::send_fin(r_content);
						r_content->m_recvstream.reset();

						SAFE_DELETE_ARRAY(memdata);
						return;
					}

					if (msgtype == SSH2_MSG_SERVICE_REQUEST)
					{
						// -------------
						byte* ptr = sendbuff;
						ptr += 4; // skip size
						ptr += 1; // skip padding size
						*ptr = SSH2_MSG_SERVICE_ACCEPT; ptr++;

						string name = ssh_t::get_intstring(ptr2);
						if (name == "ssh-userauth")
						{
							ssh_t::set_intstring(name, ptr);
							sendsize = ptr-sendbuff;
						}
					}

					if (msgtype == SSH2_MSG_USERAUTH_REQUEST)
					{
						string username    = ssh_t::get_intstring(ptr2);
						string servicename = ssh_t::get_intstring(ptr2);
						string methodname  = ssh_t::get_intstring(ptr2);

						bool   authok = false;

					//	if (servicename == "ssh-connection")
					//	if (methodname  == "none")
						{
						}

						if (servicename == "ssh-connection")
						if (methodname  == "password")
						{
							// check if client wants to change password
							bool   change_password = ssh_t::get_boolean(ptr2);
							string user_password = ssh_t::get_intstring(ptr2);

							if (user_password == "123")
							{
								authok = true;
							}
						}

						if (authok)
						{
							// Login OK
							// -------------
							byte* ptr = sendbuff;
							ptr += 4; // skip size
							ptr += 1; // skip padding size
							*ptr = SSH2_MSG_USERAUTH_SUCCESS; ptr++;

							sendsize = ptr-sendbuff;
						}
						else
						{
							// Access denied
							// -------------
							byte* ptr = sendbuff;
							ptr += 4; // skip size
							ptr += 1; // skip padding size
							*ptr = SSH2_MSG_USERAUTH_FAILURE; ptr++;

							ssh_t::set_intstring("password", ptr);
							ssh_t::set_boolean(false, ptr);

							sendsize = ptr-sendbuff;
						}
					}

					if (msgtype == SSH2_MSG_CHANNEL_OPEN)
					{
						string type_name   = ssh_t::get_intstring(ptr2);
						int    chan_id     = ssh_t::get_uint32(ptr2); // =256
						int    recv_window = ssh_t::get_uint32(ptr2);
						int    recv_maxlen = ssh_t::get_uint32(ptr2);

						// -------------
						byte* ptr = sendbuff;
						ptr += 4; // skip size
						ptr += 1; // skip padding size
						*ptr = SSH2_MSG_CHANNEL_OPEN_CONFIRMATION; ptr++;

						uint remote_id = 123;
						ssh_t::set_uint32(chan_id,     ptr); // =256
						ssh_t::set_uint32(remote_id,   ptr);
						ssh_t::set_uint32(recv_window, ptr);
						ssh_t::set_uint32(recv_maxlen, ptr);

						sendsize = ptr-sendbuff;
					}

					if (msgtype == SSH2_MSG_CHANNEL_REQUEST)
					{
						int    remote_id  = ssh_t::get_uint32(ptr2);   // =123
						string exec       = ssh_t::get_intstring(ptr2);
						bool   needreply  = ssh_t::get_boolean(ptr2);

						if (needreply)
						{
							if (exec == "subsystem" || exec == "exec")
							{
								string exec_cmd = ssh_t::get_intstring(ptr2); // sftp
								int df = 34;
							}
						}

						if (needreply)
						{
							// -------------
							byte* ptr = sendbuff;
							ptr += 4; // skip size
							ptr += 1; // skip padding size
							*ptr = SSH2_MSG_CHANNEL_SUCCESS; ptr++;

							ssh_t::set_uint32(remote_id,  ptr);

							sendsize = ptr-sendbuff;
						}
					}

					if (msgtype == SSH2_MSG_CHANNEL_DATA)
					{
						int    chan_id   = 256; // = 256(单通道)
						int    remote_id = ssh_t::get_uint32(ptr2); // =123
						int    str_len   = ssh_t::get_uint32(ptr2);
						byte*  str_ptr   = ptr2;

						// 需要管道拼接，会粘包，不能马上处理
						sftp_stream.append(str_ptr, str_len);
						ptr2 += str_len;

						if (sftp_stream.size() > 4)
						{
							// https://tools.ietf.org/html/draft-ietf-secsh-filexfer-05
							const byte* sptr = sftp_stream.begin(0);
							int packsize = GET_INT32_BIGENDIAN(sptr);

							if (sftp_stream.size()-4 >= packsize)
							{
								int   binsize = 0;
								byte* bindata = sftp_stream.fetch(binsize);

								byte*  ptr3      = bindata+4;
								byte   sftp_type = *ptr3++; 

// client to server
#define SSH2_FXP_INIT				1
#define SSH2_FXP_OPEN				3
#define SSH2_FXP_CLOSE				4
#define SSH2_FXP_READ				5
#define SSH2_FXP_WRITE				6
#define SSH2_FXP_LSTAT				7
#define SSH2_FXP_STAT_VERSION_0		7
#define SSH2_FXP_FSTAT				8
#define SSH2_FXP_SETSTAT			9
#define SSH2_FXP_FSETSTAT			10
#define SSH2_FXP_OPENDIR			11
#define SSH2_FXP_READDIR			12
#define SSH2_FXP_REMOVE				13
#define SSH2_FXP_MKDIR				14
#define SSH2_FXP_RMDIR				15
#define SSH2_FXP_REALPATH			16
#define SSH2_FXP_STAT				17
#define SSH2_FXP_RENAME				18
#define SSH2_FXP_READLINK			19
#define SSH2_FXP_SYMLINK			20

// server to client
#define SSH2_FXP_VERSION			2
#define SSH2_FXP_STATUS				101
#define SSH2_FXP_HANDLE				102
#define SSH2_FXP_DATA				103
#define SSH2_FXP_NAME				104
#define SSH2_FXP_ATTRS				105

// 表示文件的状态
#define SSH_FX_OK                   0
#define SSH_FX_EOF                  1
#define SSH_FX_NO_SUCH_FILE         2
#define SSH_FX_PERMISSION_DENIED    3
#define SSH_FX_FAILURE              4
#define SSH_FX_BAD_MESSAGE          5
#define SSH_FX_NO_CONNECTION        6
#define SSH_FX_CONNECTION_LOST      7
#define SSH_FX_OP_UNSUPPORTED       8

#define SSH_FILEXFER_TYPE_REGULAR          1
#define SSH_FILEXFER_TYPE_DIRECTORY        2
#define SSH_FILEXFER_TYPE_SYMLINK          3
#define SSH_FILEXFER_TYPE_SPECIAL          4
#define SSH_FILEXFER_TYPE_UNKNOWN          5
#define SSH_FILEXFER_TYPE_SOCKET           6
#define SSH_FILEXFER_TYPE_CHAR_DEVICE      7
#define SSH_FILEXFER_TYPE_BLOCK_DEVICE     8
#define SSH_FILEXFER_TYPE_FIFO             9

								static int count_read = 5;

								if (sftp_type == SSH2_FXP_OPENDIR)
								{
									string currdir = "/opendir/";

									uint   msg_id   = ssh_t::get_uint32(ptr3);
									string realpath = ssh_t::get_intstring(ptr3);

									// -------------
									byte* ptr = sendbuff;
									ptr += 4; // skip size
									ptr += 1; // skip padding size
									*ptr = SSH2_MSG_CHANNEL_DATA; ptr++;

									ssh_t::set_uint32(chan_id,  ptr);
									ssh_t::set_uint32(1+4+(4+currdir.size())+4,  ptr);

									// ------------
									ssh_t::set_uint32(1+4+(4+currdir.size()),  ptr);
									*ptr = SSH2_FXP_HANDLE; ptr++;
									ssh_t::set_uint32(msg_id,     ptr);
									ssh_t::set_intstring(currdir, ptr);

									sendsize = ptr-sendbuff;

									count_read = 5;
								}

								if (sftp_type == SSH2_FXP_READDIR)
								{
									// 有可能是多个文件
									string filename = "filename";
									string longname = "longname";
									uint   fileattr = 0;

									uint   msg_id  = ssh_t::get_uint32(ptr3);
									string pathdir = ssh_t::get_intstring(ptr3);

									count_read--;
									if (count_read <= 0)
									{
										// 这个消息会递归，如果完成，最后完成需要发送 0 name count
										// -------------
										byte* ptr = sendbuff;
										ptr += 4; // skip size
										ptr += 1; // skip padding size
										*ptr = SSH2_MSG_CHANNEL_DATA; ptr++;

										ssh_t::set_uint32(chan_id,  ptr);
										ssh_t::set_uint32(1+4+4+4,  ptr);

										// ------------
										ssh_t::set_uint32(1+4+4,  ptr);
										*ptr = SSH2_FXP_NAME; ptr++;
										ssh_t::set_uint32(msg_id,     ptr);
										ssh_t::set_uint32(0,          ptr); // name count
										sendsize = ptr-sendbuff;
									}
									else
									{
										// -------------
										byte* ptr = sendbuff;
										ptr += 4; // skip size
										ptr += 1; // skip padding size
										*ptr = SSH2_MSG_CHANNEL_DATA; ptr++;

										ssh_t::set_uint32(chan_id,  ptr);
										ssh_t::set_uint32(1+4+4+(4+filename.size()+4+longname.size()+4)+4,  ptr);

										// ------------
										ssh_t::set_uint32(1+4+4+(4+filename.size()+4+longname.size()+4),  ptr);
										*ptr = SSH2_FXP_NAME; ptr++;
										ssh_t::set_uint32(msg_id,    ptr);
										ssh_t::set_uint32(1,         ptr); // name count

										ssh_t::set_intstring(filename, ptr);
										ssh_t::set_intstring(longname, ptr);
										ssh_t::set_uint32(fileattr, ptr);

										sendsize = ptr-sendbuff;
									}
								}

								if (sftp_type == SSH2_FXP_CLOSE)
								{
									uint   msg_id = ssh_t::get_uint32(ptr3);
									string handle = ssh_t::get_intstring(ptr3);

									// -------------
									byte* ptr = sendbuff;
									ptr += 4; // skip size
									ptr += 1; // skip padding size
									*ptr = SSH2_MSG_CHANNEL_DATA; ptr++;

									ssh_t::set_uint32(chan_id,  ptr);
									ssh_t::set_uint32(1+4+4+4,  ptr);

									// ------------
									ssh_t::set_uint32(1+4+4,  ptr);
									*ptr = SSH2_FXP_STATUS; ptr++;
									ssh_t::set_uint32(msg_id,     ptr);
									ssh_t::set_uint32(SSH_FX_OK,  ptr); // code

									sendsize = ptr-sendbuff;
								}

								if (sftp_type == SSH2_FXP_REALPATH)
								{
									string currdir = "/root/test/";

									uint   msg_id   = ssh_t::get_uint32(ptr3);
									string realpath = ssh_t::get_intstring(ptr3);

									// -------------
									byte* ptr = sendbuff;
									ptr += 4; // skip size
									ptr += 1; // skip padding size
									*ptr = SSH2_MSG_CHANNEL_DATA; ptr++;

									ssh_t::set_uint32(chan_id,  ptr);
									ssh_t::set_uint32(1+4+4+(4+currdir.size())+4,  ptr);

									// ------------
									ssh_t::set_uint32(1+4+4+(4+currdir.size()),  ptr);
									*ptr = SSH2_FXP_NAME; ptr++;
									ssh_t::set_uint32(msg_id,     ptr); // msg_id
									ssh_t::set_uint32(1,          ptr); // name count
									ssh_t::set_intstring(currdir, ptr);
										
									sendsize = ptr-sendbuff;
								}

								if (sftp_type == SSH2_FXP_INIT)
								{
									// 有一个version
									int sftp_version = ssh_t::get_uint32(ptr3);
									CHK(sftp_version == 3 || sftp_version == 5);

// 暂时只支持sftp_version = 3, 大于的话，需要添加SSH_FILEXFER_TYPE_REGULAR
sftp_version = 3;
									// -------------
									byte* ptr = sendbuff;
									ptr += 4; // skip size
									ptr += 1; // skip padding size
									*ptr = SSH2_MSG_CHANNEL_DATA; ptr++;

									ssh_t::set_uint32(chan_id,  ptr);
									ssh_t::set_uint32(5+4,  ptr);

									ssh_t::set_uint32(5,  ptr);
									*ptr = SSH2_FXP_VERSION; ptr++;
									ssh_t::set_uint32(sftp_version,  ptr);

									sendsize = ptr-sendbuff;
								}

								int remainsize = (4+packsize) - (ptr3 - bindata);
								CHK(remainsize >= 0);

								sftp_stream.append(bindata + (4+packsize), binsize - (4+packsize));
								delete[] bindata;
							}
						}
					}

					string msgtypestr = "";

					if (msgtype == SSH2_MSG_DISCONNECT         ) msgtypestr = "SSH2_MSG_DISCONNECT";
					if (msgtype == SSH2_MSG_IGNORE             ) msgtypestr = "SSH2_MSG_IGNORE";
					if (msgtype == SSH2_MSG_UNIMPLEMENTED      ) msgtypestr = "SSH2_MSG_UNIMPLEMENTED";
					if (msgtype == SSH2_MSG_DEBUG              ) msgtypestr = "SSH2_MSG_DEBUG";
					if (msgtype == SSH2_MSG_SERVICE_REQUEST    ) msgtypestr = "SSH2_MSG_SERVICE_REQUEST";
					if (msgtype == SSH2_MSG_SERVICE_ACCEPT     ) msgtypestr = "SSH2_MSG_SERVICE_ACCEPT";

					if (msgtype == SSH2_CMSG_EOF               ) msgtypestr = "SSH2_CMSG_EOF";
					if (msgtype == SSH2_MSG_KEXINIT            ) msgtypestr = "SSH2_MSG_KEXINIT";
					if (msgtype == SSH2_MSG_NEWKEYS            ) msgtypestr = "SSH2_MSG_NEWKEYS";
					if (msgtype == SSH2_MSG_KEXDH_INIT         ) msgtypestr = "SSH2_MSG_KEXDH_INIT";
					if (msgtype == SSH2_MSG_KEXDH_REPLY        ) msgtypestr = "SSH2_MSG_KEXDH_REPLY";

					if (msgtype == SSH2_MSG_USERAUTH_REQUEST   ) msgtypestr = "SSH2_MSG_USERAUTH_REQUEST";
					if (msgtype == SSH2_MSG_USERAUTH_FAILURE   ) msgtypestr = "SSH2_MSG_USERAUTH_FAILURE";
					if (msgtype == SSH2_MSG_USERAUTH_SUCCESS   ) msgtypestr = "SSH2_MSG_USERAUTH_SUCCESS";
					if (msgtype == SSH2_MSG_USERAUTH_BANNER    ) msgtypestr = "SSH2_MSG_USERAUTH_BANNER ";

					if (msgtype == SSH2_MSG_GLOBAL_REQUEST            ) msgtypestr = "SSH2_MSG_GLOBAL_REQUEST";
					if (msgtype == SSH2_MSG_REQUEST_SUCCESS           ) msgtypestr = "SSH2_MSG_REQUEST_SUCCESS";
					if (msgtype == SSH2_MSG_REQUEST_FAILURE           ) msgtypestr = "SSH2_MSG_REQUEST_FAILURE";
					if (msgtype == SSH2_MSG_CHANNEL_OPEN              ) msgtypestr = "SSH2_MSG_CHANNEL_OPEN";
					if (msgtype == SSH2_MSG_CHANNEL_OPEN_CONFIRMATION ) msgtypestr = "SSH2_MSG_CHANNEL_OPEN_CONFIRMATION";
					if (msgtype == SSH2_MSG_CHANNEL_OPEN_FAILURE      ) msgtypestr = "SSH2_MSG_CHANNEL_OPEN_FAILURE";
					if (msgtype == SSH2_MSG_CHANNEL_WINDOW_ADJUST     ) msgtypestr = "SSH2_MSG_CHANNEL_WINDOW_ADJUST";
					if (msgtype == SSH2_MSG_CHANNEL_DATA              ) msgtypestr = "SSH2_MSG_CHANNEL_DATA";
					if (msgtype == SSH2_MSG_CHANNEL_EXTENDED_DATA     ) msgtypestr = "SSH2_MSG_CHANNEL_EXTENDED_DATA";
					if (msgtype == SSH2_MSG_CHANNEL_EOF               ) msgtypestr = "SSH2_MSG_CHANNEL_EOF";
					if (msgtype == SSH2_MSG_CHANNEL_CLOSE             ) msgtypestr = "SSH2_MSG_CHANNEL_CLOSE";
					if (msgtype == SSH2_MSG_CHANNEL_REQUEST           ) msgtypestr = "SSH2_MSG_CHANNEL_REQUEST";
					if (msgtype == SSH2_MSG_CHANNEL_SUCCESS           ) msgtypestr = "SSH2_MSG_CHANNEL_SUCCESS";
					if (msgtype == SSH2_MSG_CHANNEL_FAILURE           ) msgtypestr = "SSH2_MSG_CHANNEL_FAILURE";

					logout("msgtype=%s(%d)\n", (const char*)msgtypestr, msgtype);

					int remainsize = memsize-packlen-4;
					if (remainsize > 0)
					{
						datastream->append(memdata+packlen+4, remainsize);
					}

					if (sendsize)
					{
						// Arbitrary-length padding, such that the total length of
						// (packet_length || padding_length || payload || random padding)
						// is a multiple of the cipher block size or 8, whichever is
						// larger. There MUST be at least four bytes of padding.
						int n;
						for (n=4;n<32;n++)
						{
							if (((sendsize+n) % 16) == 0)
							{
								// random padding
								randomBlock(sendbuff+sendsize, n); sendsize += n;
								break;
							}
						}

						sendbuff[4] = n; // padding
						SET_INT32_BIGENDIAN(sendsize-4, sendbuff);

						senddata(r_content, obj, sendbuff, sendsize);
					}

					if (msgtype == SSH2_MSG_NEWKEYS)
					{
						obj->m_encrypton = 1;
					}

					SAFE_DELETE_ARRAY(memdata);

					if (datastream->size() >= 4)
					{
						packptr = datastream->begin(0);
						packlen = GET_INT32_BIGENDIAN(packptr);
						continue;
					}

					break;
				}
			}
		}
	}

public:
	static void senddata(content_t* r_content, ssh2object_t* r_obj, byte* r_data, int r_size)
	{
		ssl_t* ssl = &r_obj->m_ssl;

		if (r_obj->m_encrypton)
		{
			byte blockdata[16];
			SET_INT32_BIGENDIAN(r_obj->m_out_sequenceid, blockdata);
			r_obj->m_hmac_out.Update(blockdata, 4);

			int offset = 0;
			while(r_size-offset >= 16)
			{
				r_obj->m_hmac_out.Update(r_data+offset, 16);

				aes_t::cbc_encrypt(&ssl->m_encrypt.aeskey, r_data+offset, r_data+offset, 16);
				offset += 16;
			}

			ASSERTIF(r_size-offset > 0);

			r_obj->m_hmac_out.Final(r_data+offset);

			r_obj->m_out_sequenceid++;
			network_t::senddata(r_content, r_data, r_size+20);
			return;
		}

		r_obj->m_out_sequenceid++;
		network_t::senddata(r_content, r_data, r_size);
	}
};

extern bool webserver_init();
extern bool g_quitevent;

void ssh_server()
{
	if (webserver_init() == false)
	{
		logout("webserver_t::init failed!\n");
		return;
	}

	httplisten_t listen;
	listen.m_listen_protocol = PROTOCOL_RAW;

	if (listen.binding(222) == false)
	{
		logout("listen.binding failed!\n");
		return;
	}

	int totalbyte = 0;
	while(listen.loop(&totalbyte))
	{
		int i;
		for (i=0;i<listen.m_content.size();i++)
		{
			content_t* content = listen.m_content[i];

			if (content->m_activetime)
			{
				if (timeutil_t::get_utctime() - content->m_activetime > 100) // 100 second
				{
					// remote 100 second timeout, disconnect
					content->m_activetime = timeutil_t::get_utctime();
					network_t::send_fin(content);
					continue;
				}
			}

			sshserver_t::process(content);
		}

		if (g_quitevent)
		{
			for (i=listen.m_content.size()-1;i>=0;i--)
				listen.disconnect(listen.m_content[i]);

			break;
		}

		Sleep(listen.m_content.size() ? 20 : 100); // 10 = 500kb/s, 20 = 250kb/s
	}

	listen.unbinding();
	logout("exit\n");
}

