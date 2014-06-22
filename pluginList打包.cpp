#include <stdio.h>
#include <windows.h>
#include <time.h>
#include "QQCrypt.h"

int main()
{
    srand(time(NULL));
    puts("本工具由shuax制作，www.shuax.com。\n\n");

    int count = 0;
    int file_size = 8;
    int have_bufHash = 0;
    WIN32_FIND_DATA ffbuf;
    HANDLE hfind = FindFirstFile("pluginList\\*.*", &ffbuf);
    if (hfind != INVALID_HANDLE_VALUE)
    {
        do
        {
            if(memcmp(ffbuf.cFileName,"com.tencent",11)==0 || strcmp(ffbuf.cFileName,"bufHash")==0)
            {
                if(have_bufHash==0 && strcmp(ffbuf.cFileName,"bufHash")==0)
                {
                    have_bufHash = 1;
                }
                
                char file_name[256];
                sprintf(file_name,"pluginList\\%s",ffbuf.cFileName);

                FILE *fp = fopen(file_name,"rb");
                if(fp)
                {
                    fseek( fp, 0, SEEK_END);
                    file_size += ftell(fp);
                    fclose(fp);
                }
                //printf("%s\n",ffbuf.cFileName);
                count++;
            }
        }
        while (FindNextFile(hfind, &ffbuf));
        FindClose(hfind);
    }
    printf("共发现%d个需要打包的组件。开始构建pluginList.db。\n",count);

    unsigned char *buf = (unsigned char*)malloc(file_size+2000);
    unsigned char *out = (unsigned char*)malloc(file_size+2000);

    unsigned char *org = buf;

    *(DWORD*)buf = 0x01014154;
    buf += 4;

    *(DWORD*)buf = count;
    buf += 4;
    
    if(have_bufHash)
    {
        printf("\n发现节点 bufHash");
        
        FILE *fp = fopen("pluginList\\bufHash","rb");
        if(fp)
        {
            fseek( fp, 0, SEEK_END);
            int length = ftell(fp);
            fseek( fp, 0, SEEK_SET);

            fread(buf,1,length,fp);
            buf += length;

            fclose(fp);
        }
    }

    hfind = FindFirstFile("pluginList\\*.*", &ffbuf);
    if (hfind != INVALID_HANDLE_VALUE)
    {
        do
        {
            if(memcmp(ffbuf.cFileName,"com.tencent",11)==0)
            {
                printf("\n发现插件 %s",ffbuf.cFileName);

                char file_name[256];
                sprintf(file_name,"pluginList\\%s",ffbuf.cFileName);

                FILE *fp = fopen(file_name,"rb");
                if(fp)
                {
                    fseek( fp, 0, SEEK_END);
                    int length = ftell(fp);
                    fseek( fp, 0, SEEK_SET);

                    fread(buf,1,length,fp);
                    buf += length;

                    fclose(fp);
                }
            }
        }
        while (FindNextFile(hfind, &ffbuf));
        FindClose(hfind);
    }

	//解密
	out[0]=0;
	out[1]=0;
	unsigned long i = file_size;
	encrypt_msg(org, i, key_db, out+2, &i);

    FILE *pluginlist = fopen("pluginList.db","wb");
    fwrite(out,1,i+2,pluginlist);
    fclose(pluginlist);

    puts("\n\npluginList.db打包完成。");
    getchar();
}
