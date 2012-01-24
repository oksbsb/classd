/*
	This utility will take the Vineyard metadata csv file as input
	and generate the Application Control Application List table
	that we display in the Wiki.  It just spits out what it finds
	in the file, so you may need to tweak the column headers
	if you don't like the names that Vineyard gave them.
*/

#include <string.h>
#include <stdio.h>

char		buffer[10240];
char		filename[256] = "vineyard.csv";

int main(int argc,char *argv[])
{
FILE		*file;
char		capture[8][1024];
char		*check,*find;
int			lines,len,x;
int			offset,index;
int			qflag,eflag;

if (argc > 1) strcpy(filename,argv[1]);
file = fopen(filename,"r");

	if (file == NULL)
	{
	printf("Unable to open %s\n",filename);
	return(1);
	}

lines = 0;

printf("{| width=100%% border=\"1\" cellpadding=\"2\"\r\n");

	for(;;)
	{
	// grab a line from the file
	check = fgets(buffer,sizeof(buffer),file);
	if (check == NULL) break;

	// trim off any LF or CR characters
	find = strchr(buffer,'\n');
	if (find != NULL) *find = 0;
	find = strchr(buffer,'\r');
	if (find != NULL) *find = 0;

	len = strlen(buffer);

	// wipe the capture buffers and clear state variables
	memset(capture,0,sizeof(capture));
	qflag = eflag = 0;
	offset = 0;
	index = 0;

		for(x = 0;x < len;x++)
		{
			// if we find a comma and we're not processing a quoted
			// string then we index to the next field
			if ((buffer[x] == ',') && (qflag == 0))
			{
			offset = 0;
			index++;
			continue;
			}

			// if we find a quote toggle the qflag
			if (buffer[x] == '"')
			{
			qflag = (qflag ? 0 : 1);
			continue;
			}

			// handle escaped quote characters within quoted field
			if ((qflag != 0) && (buffer[x] == '\\') && (buffer[x+1] == '"'))
			{
			x++;
			}

		capture[index][offset] = buffer[x];
		offset++;
		}

	printf("|-\r\n");
	for(x = 0;x < 6;x++) printf("|%s\r\n",capture[x]);
	}

printf("|}\r\n");

fclose(file);
return(0);
}

