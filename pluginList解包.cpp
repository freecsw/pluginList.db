#include <stdio.h>
#include <windows.h>
#include "QQCrypt.h"

BYTE Get_BYTE(BYTE **buf)
{
    BYTE *ptr = (BYTE*)*buf;
    *buf += sizeof(BYTE);
    return *ptr;
}
WORD Get_WORD(BYTE **buf)
{
    WORD *ptr = (WORD*)*buf;
    *buf += sizeof(WORD);
    return *ptr;
}
DWORD Get_DWORD(BYTE **buf)
{
    DWORD *ptr = (DWORD*)*buf;
    *buf += sizeof(DWORD);
    return *ptr;
}

int main()
{
    puts("本工具由shuax制作，www.shuax.com。\n\n");
    FILE *fp = fopen("pluginList.db","rb");
    if(!fp)
    {
        puts("pluginList.db文件打开失败！");
        getchar();
        return 0;
    }
    fseek( fp, 0, SEEK_END);
    int file_size = ftell(fp);
    fseek( fp, 0, SEEK_SET);

    unsigned char *buf = (unsigned char*)malloc(file_size+2000);
    unsigned char *out = (unsigned char*)malloc(file_size+2000);

    fread(buf,1,file_size,fp);
    fclose(fp);

    if(buf[0]!=0||buf[1]!=0)
    {
        puts("pluginList.db文件格式不正确！");
        getchar();
        return 0;
    }

    //解密
    unsigned long real_size = file_size-2;
    decrypt_msg(buf + 2, real_size, key_db, out, &real_size);

    //
    unsigned char *gmd = out;
    if( 0x01014154!=Get_DWORD(&gmd) )
    {
        puts("pluginList.db解密失败！");
        getchar();
        return 0;
    }

    CreateDirectory("pluginList",NULL);

    DWORD count = Get_DWORD(&gmd);
    printf("共发现%d个需要解包的组件。开始解包pluginList.db。\n",count);

    for(int i=0;i<count;i++)
    {
        BYTE type = Get_BYTE(&gmd);
        DWORD length = Get_DWORD(&gmd);
        unsigned char *offset = gmd;
        DWORD sign = Get_DWORD(&gmd);

        if(type!=0xB || sign!=0x01014454)
        {
            puts("pluginList.db内部读取失败！");
            getchar();
            return 0;
        }

        int c = Get_WORD(&gmd);
        for(int j=0;j<c;j++)
        {
            //
            BYTE sub_type = Get_BYTE(&gmd);
            WORD sub_len = Get_WORD(&gmd);
            unsigned char *temp = gmd;
            
            if(c==1)
            {
                printf("\n发现节点 bufHash");
                FILE *out = fopen("pluginList\\bufHash","wb");
                fwrite(offset-5,1,length+5,out);
                fclose(out);
                break;
            }

            if(c!=1 && j==1 && sub_type==0x08)
            {
                //
                BYTE *data = (BYTE*)malloc(sub_len+2);
                memset(data,0,sub_len+2);
                memcpy(data,gmd,sub_len);
                for(int k=0;k<sub_len;k++)
                {
                    data[k] ^= ~sub_len;
                }

                if(memcmp(data,L"strPluginName",sub_len)==0)
                {
                    free(data);

                    gmd += sub_len;

                    DWORD sub_len_part = Get_DWORD(&gmd);
                    data = (BYTE*)malloc(sub_len_part+2);
                    memset(data,0,sub_len_part+2);
                    memcpy(data,gmd,sub_len_part);
                    for(int k=0;k<sub_len_part;k++)
                    {
                        data[k] ^= ~sub_len_part;
                    }
                    printf("\n发现插件 %S",data);
                    //getchar();
                    char file_name[256];
                    sprintf(file_name,"pluginList\\%S",data);
                    FILE *out = fopen(file_name,"wb");
                    fwrite(offset-5,1,length+5,out);
                    fclose(out);
                    free(data);
                    break;
                }
                else
                {
                	free(data);
                    printf("\n插件属性读取失败！");
                }
            }

            gmd = temp + sub_len;
            DWORD fix = Get_DWORD(&gmd);
            gmd += fix;
        }

        gmd = offset + length;


        //printf("%d %X\n",i+1,type);
    }
    //BYTE *ptr = out;
    //printf("begin:%X\n",ptr);
    //if(IsValidRoot(&ptr))
    //{
		//puts("PraseRoot");
		//PraseRoot(&ptr);
    	//回写
    	/*
		out[4] = 0x26;
    	unsigned char *temp = (unsigned char*)malloc(file_size+20);
		memcpy(temp,out+0x1ce,i-449);
		memcpy(out+0xD,temp,i-449);
		i-=449;
		*/
		//encrypt_msg(out, i, key, buf+2, &i);
    	//printf("%X\n",i);
        //FILE *txd = fopen("pluginList.db.bak","wb");
        //fwrite(out,1,i,txd);
        //fclose(txd);
	//}
    puts("\n\npluginList.db解包完成。");
    getchar();
}
