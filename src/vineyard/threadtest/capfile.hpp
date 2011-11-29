#ifndef CAPFILE_HPP
#define CAPFILE_HPP

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <byteswap.h>

using namespace std;

class File
{
public:
	virtual bool Open(const char *name, const char *mode) = 0;
	virtual void Close() = 0;
	virtual size_t Read(void **buf, int size) = 0;
	virtual size_t Write(void *buf, int size) = 0;
	virtual void Reset() = 0;
};

class DiskFile : public File
{
	enum
	{
		MAX_SIZE = 16384
	};

public:
	DiskFile()
		: m_file(NULL) {}

	virtual bool Open(const char *name, const char *mode)
	{
		m_file = fopen(name, mode);
		return m_file;
	}

	virtual void Close()
	{
		if (m_file)
			fclose(m_file);
	}

	virtual size_t Read(void **buf, int size)
	{
		if (size > MAX_SIZE)
			return -1;

		size_t res = fread(m_buffer, 1, size, m_file);
		*buf = m_buffer;
		return res;
	}

	virtual size_t Write(void *buf, int size)
	{
		return fwrite(buf, 1, size, m_file);
	}

	virtual void Reset()
	{}

private:
	FILE *m_file;
	char m_buffer[MAX_SIZE];
};


class MemFile : public File
{
public:
	MemFile()
		: m_data(NULL), m_size(0), m_index(0) {}

	virtual bool Open(const char *name, const char *mode)
	{
		if (strcmp(mode, "r"))
			return false;

		struct stat st;
		if (stat(name, &st))
			return false;

		FILE *f = fopen(name, mode);
		if (!f)
		{
			printf("Unable to open file %s\n", name);
			return false;
		}

		m_size = st.st_size;
		m_data = new unsigned char[m_size];
		if (!m_data)
		{
			printf("Unable to allocate %lu bytes\n", m_size);
			fclose(f);
			return false;
		}

		size_t res = fread(m_data, 1, m_size, f);
		fclose(f);
		if (res < m_size)
		{
			delete m_data;
			m_size = 0;
			printf("Failed reading %lu bytes\n", m_size);
			return false;
		}

		return true;
	}

	virtual void Close()
	{
		delete m_data;
		m_size = 0;
	}

	virtual size_t Read(void **buf, int size)
	{
		unsigned int s = (unsigned int) size;
		*buf = m_data + m_index;
		size_t bytes = s < (m_size - m_index) ? s : m_size - m_index;
		m_index += bytes;
		return bytes;
	}

	virtual size_t Write(void *buf, int size)
	{
		return -1;
	}

	virtual void Reset()
	{ m_index = 0; }

private:
	unsigned char *m_data;
	unsigned long m_size;
	unsigned long m_index;
};

class Capfile
{

public:
	struct pkthdr {
		u_long ts;	/* time stamp */
		bpf_u_int32 caplen;	/* length of portion present */
		bpf_u_int32 len;	/* length this packet (off wire) */
	};

	Capfile(const char *name)
		: m_name(name) {}

	bool Open(bool inmem = false)
	{
		m_file = inmem ? (File *) new MemFile : (File *) new DiskFile;
		if (!m_file || !m_file->Open(m_name.c_str(), "r"))
		{
			printf("open failed\n");
			return false;
		}

		const u_int hdrsize = sizeof(pcap_file_header);
		pcap_file_header *hdr;
		if ((m_file->Read((void **)&hdr, hdrsize) < hdrsize) || (hdr->magic != 
#ifdef __mips__
			0xd4c3b2a1))
#else
			0xa1b2c3d4))
#endif
		{
			printf("bad magic\n");
			m_file->Close();
			return false;
		}

		m_snaplen = hdr->snaplen;
		return true;
	}

	bool Create()
	{
		m_file = new DiskFile;
		if (!m_file || !m_file->Open(m_name.c_str(), "w"))
			return false;

		pcap_file_header hdr;
		hdr.magic = 0xa1b2c3d4;
		hdr.version_major = 4;
		hdr.version_minor = 2;
		hdr.thiszone = 0;
		hdr.sigfigs = 8;
		m_snaplen = hdr.snaplen = 1514;
		hdr.linktype = 0;

		if (m_file->Write(&hdr, sizeof(pcap_file_header)) < sizeof(pcap_file_header))
		{
			m_file->Close();
			return false;
		}

		return true;
	}

	u_int Read(u_char **buf, u_int size, pkthdr **header = NULL)
	{
		pkthdr *p = NULL;

		const u_int hdrsize = sizeof(pkthdr);
		if (m_file->Read((void **)&p, hdrsize) < hdrsize)
			return 0;
#ifdef __mips__
		u_int caplen = bswap_32(p->caplen);
#else
		u_int caplen = p->caplen;
#endif
		u_int len = min(size, caplen);

		if (m_file->Read((void **)buf, len) < len)
			return 0;
		if (len < caplen)
		{
			assert(caplen < 16384);
			char *tmp;
			m_file->Read((void **)&tmp, caplen - len);
		}
#if 0
		if (header)
			*header = p;
#endif
		return caplen;
	}

	u_int Write(u_char *buf, u_int size, pkthdr *header)
	{
		u_int len = header->caplen = min(size, m_snaplen);
		const u_int hdrsize = sizeof(pkthdr);
		if (m_file->Write(header, hdrsize) < hdrsize)
			return 0;

		if (m_file->Write(buf, len) < len)
			return 0;

		return len;
	}

	void Close()
	{ m_file->Close(); delete m_file; }

	void Reset()
	{ 
		m_file->Reset(); 

		const u_int hdrsize = sizeof(pcap_file_header);
		pcap_file_header *hdr;
		m_file->Read((void **)&hdr, hdrsize);
	}

private:
	string m_name;
	File *m_file;
	u_int m_snaplen;
};

#endif
