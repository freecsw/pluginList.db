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
        
        // ��������������ֽ�
        uint32_t db_size = file_size + 32;
        uint8_t *db_buf = (uint8_t*)malloc(db_size);

        // ���ͷ�������ֽ�
        db_buf[0] = db_buf[1] = 0;

        // ����
        encrypt_msg(buf, file_size, key_db, db_buf + 2, &db_size);

        // д���ļ�
        FILE *output = fopen("pluginList.db", "wb");
        fwrite(db_buf, 1, db_size + 2, output);
        fclose(output);

        free(buf);
        free(db_buf);

        puts("������ɣ����򼴽��˳���");
        system("pause");
    }
}


void decrypt()
{
    FILE *fp = fopen("pluginList.db", "rb");
    if(fp)
    {
        // db�ļ��Ŀ�ͷ�����ֽ���û�õģ����ǲ�Ҫ
        fseek(fp, 0, SEEK_END);
        uint32_t file_size = ftell(fp) - 2;
        fseek(fp, 2, SEEK_SET);

        uint8_t *buf = (uint8_t*)malloc(file_size);

        fread(buf, 1, file_size, fp);
        fclose(fp);
        
        uint32_t txd_size = file_size;
        uint8_t *txd_buf = (uint8_t*)malloc(txd_size);

        //����
        decrypt_msg(buf, file_size, key_db, txd_buf, &txd_size);

        //д���ļ�
        FILE *output = fopen("pluginList.db.txd", "wb");
        fwrite(txd_buf, 1, txd_size, output);
        fclose(output);

        free(buf);
        free(txd_buf);

        puts("������ɣ����򼴽��˳���");
        system("pause");
    }
}

int main()
{
    srand(time(NULL));
    puts("��������shuax��������վ��www.shuax.com");


    FILE *test = fopen("pluginList.db.txd", "rb");
    if(test)
    {
        fclose(test);
        puts("�������ģʽ������ pluginList.db.txd ����Ϊ pluginList.db");
        system("pause");
        encrypt();
    }
    else
    {
        test = fopen("pluginList.db", "rb");
        if(test)
        {
            fclose(test);
            puts("�������ģʽ������ pluginList.db ����Ϊ pluginList.db.txd");
            system("pause");
            decrypt();
        }
        else
        {
            puts("û���ҵ� pluginList.db �ļ��� pluginList.db.txd �ļ������򼴽��˳���");
            system("pause");
        }
    }
    return 0;
}
