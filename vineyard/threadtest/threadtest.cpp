#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <map>
#include <list>
#include <navl.h>
#include <pthread.h>
#include <string>
#include <assert.h>
#include <capfile.hpp>
#include <errno.h>

using namespace std;

u_int g_lo_threads = 1;
u_int g_hi_threads = 0;

#define NUM_FLOWS 10000
#define MAX_PKT_SIZE 1514

u_int g_num_flows = NUM_FLOWS;

pthread_t *g_thread;
string g_filelist = "filelist.txt";
string g_attrfile = "";

int g_error = 0;

static void *thread_entry(void *arg);
static int callback(navl_result_t result, navl_state_t state, void *arg, int error);
static void init(int argc, char *argv[]);
static void usage(char *prog);
static void show_version_info();
static const char *error_string(int error);
static void enable_attributes();

extern "C" { void navl_flush(); }

////////////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
	int res = 0;
	init(argc, argv);
	g_thread = new pthread_t[g_hi_threads];

	FILE *f = fopen(g_filelist.c_str(), "r");
	if (!f)
		exit(-1);

	u_int i = 0;
	Capfile *files[g_hi_threads];
	char filenames[g_hi_threads][1024];

	while (fgets(filenames[i], 1024, f) && (i < g_hi_threads))
	{
		filenames[i][strlen(filenames[i]) - 1] = '\0';
		if (!strlen(filenames[i]))
			break;

		i++;
	}

	if (i < g_hi_threads)
	{
		printf("Not enough files in filelist.txt\n");
		exit(-1);
	}

	for (u_int i = 0; i < g_hi_threads; i++)
	{
		printf("reading file %s...", filenames[i]);
		fflush(stdout);

		files[i] = new Capfile(filenames[i]);
		if (files[i]->Open(true))
		{
			printf("\n");
			fflush(stdout);
		}
		else
		{
			printf(" failed\n");
			exit(-1);
		}
	}

	for (u_int num_threads = g_lo_threads; num_threads <= g_hi_threads; num_threads++)
	{
		g_error = 0;

		if (navl_open(g_num_flows * num_threads, num_threads, "plugins") == -1)
		{
			printf("Error initializing NAVL\n");
			exit(-1);
		}

		if (!g_attrfile.empty())
			enable_attributes();

		printf("Running %d threads: ", num_threads);
		fflush(stdout);
		timeval tv_start;
		gettimeofday(&tv_start, NULL);

		for (u_int i = 0; i < num_threads; i++)
			pthread_create(&(g_thread[i]), NULL, &thread_entry, files[i]);

		for (u_int i = 0; i < num_threads; i++)
		{
			pthread_join(g_thread[i], NULL);
		}

		timeval tv_end;
		gettimeofday(&tv_end, NULL);

		double elapsed = (double)((unsigned long)((tv_end.tv_sec - tv_start.tv_sec) * 1000000) + 
			(tv_end.tv_usec - tv_start.tv_usec)) / 1000000;
		printf ("done in %.2f seconds", elapsed);
		if (g_error)
		{
			printf(" *** Error occured during test: %s", error_string(g_error));
			res = g_error;
		}
		printf("\n");

		fflush(stdout);
		navl_flush();

		navl_close();
		sleep(1);
	}

	return res;
}

static int callback(navl_result_t result, navl_state_t state, void *arg, int error)
{
	if (error && error != ENOTCONN)
		g_error = error;

	return 0;
}

static void *thread_entry(void *arg)
{
	Capfile *capfile = (Capfile *)arg;
	u_char *buf;
	int size;
	capfile->Reset();

	while ((size = capfile->Read(&buf, MAX_PKT_SIZE)) != 0) 
	{
		navl_classify(buf, size, callback, NULL);
	}

	navl_flush();
	if (g_hi_threads == 1)
		navl_diag(1);

	return NULL;
}

static void
init(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "t:T:f:n:v:a:")) != -1)
	{
		switch (c)
		{
		case 't':
			g_lo_threads = atoi(optarg);
			break;
		case 'T':
			g_hi_threads = atoi(optarg);
			break;
		case 'f':
			g_filelist = optarg;
			break;
		case 'n':
			g_num_flows = atoi(optarg);
			break;
		case 'a':
			g_attrfile = optarg;
			break;
		case 'v':
			show_version_info();
			break;
		default:
			usage(argv[0]);
		}
	}

	if (!g_lo_threads)
		usage(argv[0]);

	if (g_hi_threads < g_lo_threads)
		g_hi_threads = g_lo_threads;

	optind = 1;
	opterr = 1;
	optopt = 63;
}

static void
usage(char *prog)
{
	printf("Usage: %s [OPTION...] filename\n", prog);
	printf("  -t<num> min number of threads/files to process (default: %u)\n", g_lo_threads);
	printf("  -T<num> max number of threads/files to process (default: %u)\n", g_lo_threads);
	printf("  -f<filename> file containing list of files to process (default: %s)\n", g_filelist.c_str());
	printf("  -n<num> number of flows (default: %u)\n", g_num_flows);
	printf("  -a<filename> file containing list of attributes to enable\n");
	printf("  -v show libnavl version info and exit\n");
	exit(0);
}

static void
enable_attributes()
{
	
	FILE *f = fopen(g_attrfile.c_str(), "r");
	if (!f)
	{
		printf("Error opening file: %s\n", g_attrfile.c_str());
		exit(-1);
	}

	char nextattr[256];
	int key = 0;
	while (fgets(nextattr, 256, f))
	{
		nextattr[strlen(nextattr) - 1] = '\0';
		if ((key = navl_attr(nextattr, 1)) < 1)
		{
			printf("Attribute %s not found\n", nextattr);
			exit(-1);
		}
		printf("Enabled attribute %s : %d\n", nextattr, key);
	}
	fclose(f);
}

static void
show_version_info()
{
	navl_open(1000, 1, "plugins");
	navl_diag(1);
	navl_close();
	exit(0);
}
static const char *
error_string(int error)
{
	switch (error)
	{
	case ENOMEM:
		return "No memory available";
	case ENOBUFS:
		return "No flows available";
	case ENOSR:
		return "No resources available";
	case ENOTCONN:
		return "Missing TCP handshake";
	default:
		return "Unknown";
	}
}
