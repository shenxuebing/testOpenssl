#pragma once
#ifndef CERTINDEX
#define	CERTINDEX	1

#define DEC_INDEX_VERSION                             0    //�汾��
#define DEC_INDEX_SERIALNUMBER                        1    //֤�����к�
#define DEC_INDEX_INT_SIGNALGID                       2    //ǩ���㷨(����)
#define DEC_INDEX_STRING_SIGNALGID                    3    //ǩ���㷨(�ַ���)

#define DEC_INDEX_ISSUER_COUNTRYNAME                  5    //�䷢�߹�������
#define DEC_INDEX_ISSUER_ORGANIZATIONNAME			  6    //�䷢����֯����
#define DEC_INDEX_ISSUER_ORGANIZATIONUNITNAME         7    //�䷢�߲�������
#define DEC_INDEX_ISSUER_STATEORPROVINCENAME          8    //�䷢��ʡ��
#define DEC_INDEX_ISSUER_COMMONNAME                   9    //�䷢��ͨ����
#define DEC_INDEX_ISSUER_LOCALITYNAME                 10   //�䷢�����ڵ���
#define DEC_INDEX_ISSUER_TITLE                        11   //�䷢��ͷ��
#define DEC_INDEX_ISSUER_SURNAME                      12   //�䷢����
#define DEC_INDEX_ISSUER_GIVENNAME                    13   //�䷢����
#define DEC_INDEX_ISSUER_INITIALS                     14   //�䷢�߳���
#define DEC_INDEX_ISSUER_EMAILADDRESS                 15   //�䷢��E_Mail��ַ
#define DEC_INDEX_ISSUER_POSTALADDRESS                16   //�䷢��ͨ�ŵ�ַ
#define DEC_INDEX_ISSUER_POSTALBOX					  17   //�䷢������
#define DEC_INDEX_ISSUER_POSTALCODE                   18   //�䷢���ʱ�
#define DEC_INDEX_ISSUER_TELEPHONENUMBER              19   //�䷢�ߵ绰����
#define DEC_INDEX_ISSUER_TELEXNUMBER                  20   //�䷢�ߴ������
#define DEC_INDEX_NOTBEFORE                           21   //֤����Ч����ʼʱ��
#define DEC_INDEX_NOTAFTER                            22   //֤����Ч�ڽ���ʱ��
#define DEC_INDEX_SUBJECT_COUNTRYNAME                 23   //�����߹�������
#define DEC_INDEX_SUBJECT_ORGANIZATIONNAME            24   //��������֯����
#define DEC_INDEX_SUBJECT_ORGANIZATIONALUNITNAME      25   //�����߲�������
#define DEC_INDEX_SUBJECT_STATEORPROVINCENAME         26   //������ʡ��
#define DEC_INDEX_SUBJECT_COMMONNAME                  27   //������ͨ����
#define DEC_INDEX_SUBJEC_LOCALITYNAME                 28   //���������ڵ���
#define DEC_INDEX_SUBJEC_TITLE                        29   //������ͷ��
#define DEC_INDEX_SUBJEC_SURNAME                      30   //��������
#define DEC_INDEX_SUBJEC_GIVENNAME                    31   //��������
#define DEC_INDEX_SUBJEC_INITIALS                     32   //�����߳���
#define DEC_INDEX_SUBJEC_EMAIL                        33   //������E_Mail��ַ
#define DEC_INDEX_SUBJEC_POSTALADDRESS                34   //������ͨ�ŵ�ַ
#define DEC_INDEX_SUBJEC_POSTALOFFICEBOX              35   //����������
#define DEC_INDEX_SUBJEC_POSTALCODE                   36   //�������ʱ�
#define DEC_INDEX_SUBJEC_TELEPHONENUMBER              37   //�����ߵ绰����
#define DEC_INDEX_SUBJEC_TELEXNUMBER                  38   //�����ߴ������
#define DEC_INDEX_DERPUBKEY                           39   //DER���빫Կ
#define DEC_INDEX_USRPUBKEY                           40   //DER���빫Կ(ͬDEC_INDEX_DERPUBKEY)
#define DEC_INDEX_ISSU_UNIQUEID                       41   //�䷢��ΨһID
#define DEC_INDEX_SUBJECT_UNIQUEID                    42   //������ΨһID
#define DEC_INDEX_SUBJEC_EMAILADDRESS                 43   //������email
#define DEC_INDEX_KEYUSAGE                            44   //
#define DEC_INDEX_CRLDISTRIBUTIONPOINT4S1             45   //֤���CRL��ȡ��
#define DEC_INDEX_LEGALPERSON                         52   //��λ����--> ���ڵ�λ����
#define DEC_INDEX_BUSSINESSCODE                       53   //���ڴ��ݻ�����ID
#define DEC_INDEX_TAXCODE                             54   //
#define DEC_INDEX_CLASSNUMBER                         55   //
#define DEC_INDEX_AGENCYUNIQUEID                      57   //ҵ�������
#define DEC_INDEX_SAN_DNS                             58   //�����滻��,DNS
#define DEC_INDEX_SAN_SERVERIP                        59   //�����滻��,serverIP
#define DEC_INDEX_SERVEROS                            60   //serverOS
#define DEC_INDEX_USERADDRESS                         69   //
#define DEC_INDEX_ACCOUNT                             70   //�豸�Ż���������
#define DEC_INDEX_UNITCHARACTER                       71   //��λ����
#define DEC_INDEX_SUBJECTUSAGE                        72   //��λ������
#define DEC_INDEX_INT_CERTTYPE                        73   //֤������(����)
#define DEC_INDEX_CERTUSAGE                           74   //֤������
#define DEC_INDEX_AUTHORITYKEYID                      75   //�䷢������Կ��ʶ��
#define DEC_INDEX_SUBJECTKEYID                        76   //������Կ��ʶ��
#define DEC_INDEX_AUTHORITYINFOACCESS1                77   //ocsp��http��ldap����վ��URI1
#define DEC_INDEX_AUTHORITYINFOACCESS2                78   //ocsp��http��ldap����վ��URI2
#define DEC_INDEX_CRLDISTRIBUTIONPOINT4S2             79   //֤���CRL��ȡ��2
#define DEC_INDEX_ISCA                                80   //
#define DEC_INDEX_IDENTIFYCARDNUMBER                  81   //1.2.86.11.7.1   �й���Ϣ��ȫ��ί��֤����չ�����֤��
#define DEC_INDEX_INSURANCENUMBER                     82   //1.2.86.11.7.2   �й���Ϣ��ȫ��ί��֤����չ����ᱣ�պ�
#define DEC_INDEX_ORGNAZATIONCODE                     83   //1.2.86.11.7.3   �й���Ϣ��ȫ��ί��֤����չ����֯��������
#define DEC_INDEX_ICREGISTRATIONNUMBER                84   //1.2.86.11.7.4   �й���Ϣ��ȫ��ί��֤����չ�򣺹���ע���
#define DEC_INDEX_TAXATIONNUMEBER                     85   //1.2.86.11.7.5   �й���Ϣ��ȫ��ί��֤����չ��˰��
#define DEC_INDEX_NETSCAPECERTTYPE                    86   //
#define DEC_INDEX_ROOTSERIALNUMBER                    87   //
#define DEC_INDEX_SUBJEC_DEVICENUMBER                 88   //2.5.4.5 ����������SERIALNUBER
#define DEC_INDEX_SUBJEC_DESCRIPTION                  89   //2.5.4.13 ���������� Description
#define DEC_INDEX_PRIV_EXT_CERTUSAGE_A                90  //
#define DEC_INDEX_DC                                  91   //
#define DEC_INDEX_PRIV_EXT_LEGALPERSON                100  //���ڵ�λ����(PRIV_EXT)
#define DEC_INDEX_PRIV_EXT_BUSINESSCODE               101  //��ᱣ�պ�(PRIV_EXT)
#define DEC_INDEX_PRIV_EXT_TAXCODE                    102  //
#define DEC_INDEX_PRIV_EXT_AGENCYUNIQUEID             103  //
#define DEC_INDEX_PRIV_EXT_SERVERDNS                  104  //
#define DEC_INDEX_PRIV_EXT_SERVERIP                   105  //
#define DEC_INDEX_PRIV_EXT_SERVEROS                   106  //
#define DEC_INDEX_PRIV_EXT_USERADDRESS                107  //
#define DEC_INDEX_PRIV_EXT_ACCOUNT                    108  //ע��Ψһ���
#define DEC_INDEX_PRIV_EXT_UNITCHARACTER              109  //
#define DEC_INDEX_PRIV_EXT_SUBJECTUSAGE               110  //
#define DEC_INDEX_PRIV_EXT_CERTUSAGE                  111  //
#define DEC_INDEX_HTTPADDRESS                         112  //��¼��
#define DEC_INDEX_CAEMAILADDRESS                      113  //caemail��ַ
#define DEC_INDEX_CAHTTPADDRESS                       114  //cahttp��ַ
#define DEC_INDEX_POLICY                              115  //
#define DEC_INDEX_GUID                                116  //GUID
#define DEC_INDEX_NAME                                117  //
#define DEC_INDEX_SUBJEC_GENERATIONQUALIFIER          118  //
#define DEC_INDEX_ISSUER_GENERATIONQUALIFIER          119  //
#define DEC_INDEX_SXCA1                               131  //����CA��չ1
#define DEC_INDEX_SXCA2                               132  //����CA��չ2
#define DEC_INDEX_EGOVIDENTIFYCODE                    141  //������ݱ�ʶ��(����)
#define DEC_INDEX_EGOVINSURANCENUMBER                 142  //������ᱣ�պ�(����)
#define DEC_INDEX_EGOVORGANIZEATIONCODE               143  //��ҵ��֯��������(����)
#define DEC_INDEX_EGOVICREGISTRATIONNUMBER            144  //��ҵ����ע���(����)
#define DEC_INDEX_EGOVTAXATIONNUMBER                  145  //��ҵ˰��(����)
#define DEC_INDEX_ORGANIZATIONALUNITNAME0             220  //OU0
#define DEC_INDEX_ORGANIZATIONALUNITNAME1             221  //OU1
#define DEC_INDEX_ORGANIZATIONALUNITNAME2             222  //OU2
#define DEC_INDEX_ORGANIZATIONALUNITNAME3             223  //OU3
#define DEC_INDEX_ORGANIZATIONALUNITNAME4             224  //OU4
#define DEC_INDEX_ORGANIZATIONALUNITNAME5             225  //OU5
#define DEC_INDEX_ORGANIZATIONALUNITNAME6             226  //OU6
#define DEC_INDEX_ORGANIZATIONALUNITNAME7             227  //OU7
#define DEC_INDEX_ORGANIZATIONALUNITNAME8             228  //OU8
#define DEC_INDEX_ORGANIZATIONALUNITNAME9             229  //OU9
#define DEC_INDEX_EGOVPAPERTYPE                       230  //������ݱ�ʶ��(����)-֤������
#define DEC_INDEX_EGOVPAPERCODE                       231  //������ݱ�ʶ��(����)-֤������
#define DEC_INDEX_SERVERIP                            159  //SERVERIP


#endif // !CERTINDEX
