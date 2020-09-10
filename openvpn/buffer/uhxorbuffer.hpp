// A wrapper class for logic that aids in supporting the 'uh-xor' directive.

#ifndef OPENVPN_BUFFER_UHXORBUFFER_H
#define OPENVPN_BUFFER_UHXORBUFFER_H

#include <algorithm>
#include <string>

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/buffer/bufhex.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/rc.hpp>

namespace openvpn {

OPENVPN_EXCEPTION(uh_xor_exception);

// Provides the implementation for the `uh-xor` directive, which obfuscates
// transport layer payloads with a simple XOR mask.
//
// Usage in OpenVPN config file:
//   uh-xor <ASCII hexadecimal key>
class UHXORBuffer : public RC<thread_unsafe_refcount> {
public:
	typedef RCPtr<UHXORBuffer> Ptr;

	// Creates a new UHXORBuffer that is able to obfuscate buffers by
	// applying the XOR operation on the contents with the given key,
	// key_hex - which should be in ASCII hexadecimal form.
	static Ptr new_with_string_key(const std::string &key_hex)
	{
		return Ptr(new UHXORBuffer(key_hex));
	}

	// Applies the XOR obfuscation to the given buffer, modifying it in-
	// place.
	void obfuscate(BufferAllocated &buffer)
	{
		obfuscate_buffer(buffer);
	}

	// Copies the given const buffer and then applies the XOR obfuscation
	// to it.
	BufferPtr obfuscate(const Buffer &buffer_arg)
	{
		BufferPtr buffer(new BufferAllocated(buffer_arg, BufferAllocated::ARRAY));
		obfuscate_buffer(*buffer);
		return buffer;
	}

private:
	BufferAllocated key_;

	UHXORBuffer(const std::string &key_hex)
		: key_(0, BufferAllocated::ARRAY|BufferAllocated::CONSTRUCT_ZERO|BufferAllocated::GROW)
	{
		// parse hex to byte buffer or throw exception
		try {
			parse_hex(key_, key_hex);
		} catch (const parse_hex_error&) {
		    OPENVPN_THROW(uh_xor_exception, "Failed to parse hex key string.");
		} catch (const BufferException &e) {
		    OPENVPN_THROW(uh_xor_exception, "Buffer Exception: " << e.what());
		}
	}

	// Separate small simple function to allow for auto-vectorisation...
	// The performance gains are small but hey, better than nothing!
	inline void xor_buf_with_key(
		unsigned char *buf,
		unsigned char *key,
		size_t len
	) {
		for (int i = 0; i < len; i++) {
			buf[i] ^= key[i];
		}
	}

	// Internal logic to (de)obfuscate the given buffer by XOR'ing it with
	// the key that the UHXORBuffer was initialised with.
	inline void obfuscate_buffer(BufferAllocated &buffer)
	{
		if (key_.size() == 0) return;
		auto b = buffer.data();
		while (b < buffer.data_end()) {
			size_t max = std::min((size_t) (buffer.data_end() - b),
					      key_.size());
			xor_buf_with_key(b, key_.data(), max);
			b += max;
		}
	}
};

} // openvpn

#endif // OPENVPN_BUFFER_UHXORBUFFER_H

