#include <stdio.h>
#include <time.h>
#include "QQCrypt.h"

void encrypt()
{
    FILE *fp = fopen("pluginList.db.txd", "rb");
    if(fp)
    {
        fseek(fp, 0, SEEK_END);
        uint32_t file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        uint8_t *buf = (uint8_t*)malloc(file_size);

        fread(buf, 1, file_size, fp);
        fclose(fp);
        
        // 留够对齐所需的字节
        uint32_t db_size = file_size + 32;
        uint8_t *db_buf = (uint8_t*)malloc(db_size);

        // 填充头部两个字节
        db_buf[0] = db_buf[1] = 0;

        // 加密
        encrypt_msg(buf, file_size, key_db, db_buf + 2, &db_size);

        // 写入文件
        FILE *output = fopen("pluginList.db", "wb");
        fwrite(db_buf, 1, db_size + 2, output);
        fclose(output);

        free(buf);
        free(db_buf);

        puts("加密完成，程序即将退出。");
        system("pause");
    }
}


void decrypt()
{
    FILE *fp = fopen("pluginList.db", "rb");
    if(fp)
    {
        // db文件的开头两个字节是没用的，我们不要
        fseek(fp, 0, SEEK_END);
        uint32_t file_size = ftell(fp) - 2;
        fseek(fp, 2, SEEK_SET);

        uint8_t *buf = (uint8_t*)malloc(file_size);

        fread(buf, 1, file_size, fp);
        fclose(fp);
        
        uint32_t txd_size = file_size;
        uint8_t *txd_buf = (uint8_t*)malloc(txd_size);

        //解密
        decrypt_msg(buf, file_size, key_db, txd_buf, &txd_size);

        //写入文件
        FILE *output = fopen("pluginList.db.txd", "wb");
        fwrite(txd_buf, 1, txd_size, output);
        fclose(output);

        free(buf);
        free(txd_buf);

        puts("解密完成，程序即将退出。");
        system("pause");
    }
}

int main()
{
    srand(time(NULL));
    puts("本工具由shuax制作，网站：www.shuax.com");


    FILE *test = fopen("pluginList.db.txd", "rb");
    if(test)
    {
        fclose(test);
        puts("进入加密模式，将把 pluginList.db.txd 加密为 pluginList.db");
        system("pause");
        encrypt();
    }
    else
    {
        test = fopen("pluginList.db", "rb");
        if(test)
        {
            fclose(test);
            puts("进入解密模式，将把 pluginList.db 解密为 pluginList.db.txd");
            system("pause");
            decrypt();
        }
        else
        {
            puts("没有找到 pluginList.db 文件或 pluginList.db.txd 文件，程序即将退出。");
            system("pause");
        }
    }
    return 0;
}
