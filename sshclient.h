/* 
 * 2024/07/03
 * ssh client
 */

#ifndef __sshclient_h__
#define __sshclient_h__

#include <net/network.h>
#include <ssl/sslv2.h>

class ssh2object_t : public coreobject_t
{
public:
	ssh2object_t()
	{
		m_in_sequenceid  = 0;
		m_out_sequenceid = 0;

		m_encrypton      = 0;
	}

	virtual ~ssh2object_t()
	{
	}

public:
	ssl_t    m_ssl;

	string   m_versioncli;
	string   m_versionsvr;

	byte     m_session_id[20];
	hmac_t   m_hmac_in;
	hmac_t   m_hmac_out;

	int      m_in_sequenceid;
	int      m_out_sequenceid;
	int      m_encrypton;
};

// message numbers
#define SSH2_MSG_DISCONNECT           1
#define SSH2_MSG_IGNORE               2
#define SSH2_MSG_UNIMPLEMENTED        3
#define SSH2_MSG_DEBUG                4
#define SSH2_MSG_SERVICE_REQUEST      5
#define SSH2_MSG_SERVICE_ACCEPT       6

#define SSH2_CMSG_EOF                19
#define SSH2_MSG_KEXINIT             20
#define SSH2_MSG_NEWKEYS             21
#define SSH2_MSG_KEXDH_INIT          30
#define SSH2_MSG_KEXDH_REPLY         31

// userauth message numbers
#define SSH2_MSG_USERAUTH_REQUEST    50
#define SSH2_MSG_USERAUTH_FAILURE    51
#define SSH2_MSG_USERAUTH_SUCCESS    52
#define SSH2_MSG_USERAUTH_BANNER     53

#define SSH2_MSG_GLOBAL_REQUEST              80
#define SSH2_MSG_REQUEST_SUCCESS             81
#define SSH2_MSG_REQUEST_FAILURE             82
#define SSH2_MSG_CHANNEL_OPEN                90
#define SSH2_MSG_CHANNEL_OPEN_CONFIRMATION   91
#define SSH2_MSG_CHANNEL_OPEN_FAILURE        92
#define SSH2_MSG_CHANNEL_WINDOW_ADJUST       93
#define SSH2_MSG_CHANNEL_DATA                94
#define SSH2_MSG_CHANNEL_EXTENDED_DATA       95
#define SSH2_MSG_CHANNEL_EOF                 96
#define SSH2_MSG_CHANNEL_CLOSE               97
#define SSH2_MSG_CHANNEL_REQUEST             98
#define SSH2_MSG_CHANNEL_SUCCESS             99
#define SSH2_MSG_CHANNEL_FAILURE             100

class ssh_t
{
public:
	static string get_intstring(byte*& r_ptr)
	{
		string str;
		int    str_len = GET_INT32_BIGENDIAN(r_ptr);	r_ptr += 4;
		str.copymemory(r_ptr, str_len);             	r_ptr += str_len;

		return str;
	}

	static bool get_boolean(byte*& r_ptr)
	{
		int value = *r_ptr;  r_ptr++;
		if (value == 1) return true;

		return false;
	}

	static uint get_uint32(byte*& r_ptr)
	{
		uint   value = GET_INT32_BIGENDIAN(r_ptr); r_ptr += 4;
		return value;
	}

	static rsa4096_t get_integer(byte*& r_ptr)
	{
		rsa4096_t C;

		uint length = GET_INT32_BIGENDIAN(r_ptr); r_ptr += 4;
		asn_t::decode_integer(r_ptr, length, (byte*)&C);

		return C;
	}

public:
	static void set_intstring(const char* r_str, byte*& r_ptr)
	{
		int length = strlen(r_str);

		SET_INT32_BIGENDIAN(length, r_ptr); r_ptr += 4;
		CopyMemory(r_ptr, r_str, length);   r_ptr += length;
	}

	static bool set_boolean(bool r_value, byte*& r_ptr)
	{
		*r_ptr = (r_value?1:0); r_ptr++;
		return false;
	}

	static void set_uint32(uint r_value, byte*& r_ptr)
	{
		SET_INT32_BIGENDIAN(r_value, r_ptr); r_ptr += 4;
	}

	static void set_integer(rsa4096_t& C, int r_bytesize, byte*& r_ptr)
	{
		int length = asn_t::encode_integer_internal((const byte*)&C, r_bytesize, r_ptr+4);
		set_uint32(length, r_ptr); r_ptr += length;
	}

	static void set_rsa_sign(rsa4096_t& R, int r_bytesize, byte*& r_ptr)
	{
		byte* startptr = r_ptr; r_ptr += 4; // skip block length

		set_intstring("ssh-rsa", r_ptr);
		set_integer(R, r_bytesize, r_ptr);

		SET_INT32_BIGENDIAN(r_ptr-startptr-4, startptr);
	}

	static void set_rsa_pubkey(rsakey_t* r_pubkey, byte*& r_ptr)
	{
		byte* startptr = r_ptr; r_ptr += 4; // skip block length

		set_intstring("ssh-rsa", r_ptr);

		int length = 0;

		length = asn_t::encode_integer_internal((const byte*)&r_pubkey->m_e, 3, r_ptr+4);
		set_uint32(length, r_ptr); r_ptr += length;

		length = asn_t::encode_integer_internal((const byte*)r_pubkey->m_modulus, r_pubkey->getBitSize()/8, r_ptr+4);
		set_uint32(length, r_ptr); r_ptr += length;

		SET_INT32_BIGENDIAN(r_ptr-startptr-4, startptr);
	}
};

#endif // __sshclient_h__
