#pragma once
#ifndef CERTINDEX
#define	CERTINDEX	1

#define DEC_INDEX_VERSION                             0    //版本号
#define DEC_INDEX_SERIALNUMBER                        1    //证书序列号
#define DEC_INDEX_INT_SIGNALGID                       2    //签名算法(整数)
#define DEC_INDEX_STRING_SIGNALGID                    3    //签名算法(字符串)

#define DEC_INDEX_ISSUER_COUNTRYNAME                  5    //颁发者国家名称
#define DEC_INDEX_ISSUER_ORGANIZATIONNAME			  6    //颁发者组织名称
#define DEC_INDEX_ISSUER_ORGANIZATIONUNITNAME         7    //颁发者部门名称
#define DEC_INDEX_ISSUER_STATEORPROVINCENAME          8    //颁发者省名
#define DEC_INDEX_ISSUER_COMMONNAME                   9    //颁发者通用名
#define DEC_INDEX_ISSUER_LOCALITYNAME                 10   //颁发者所在地名
#define DEC_INDEX_ISSUER_TITLE                        11   //颁发者头衔
#define DEC_INDEX_ISSUER_SURNAME                      12   //颁发者姓
#define DEC_INDEX_ISSUER_GIVENNAME                    13   //颁发者名
#define DEC_INDEX_ISSUER_INITIALS                     14   //颁发者初名
#define DEC_INDEX_ISSUER_EMAILADDRESS                 15   //颁发者E_Mail地址
#define DEC_INDEX_ISSUER_POSTALADDRESS                16   //颁发者通信地址
#define DEC_INDEX_ISSUER_POSTALBOX					  17   //颁发者信箱
#define DEC_INDEX_ISSUER_POSTALCODE                   18   //颁发者邮编
#define DEC_INDEX_ISSUER_TELEPHONENUMBER              19   //颁发者电话号码
#define DEC_INDEX_ISSUER_TELEXNUMBER                  20   //颁发者传真号码
#define DEC_INDEX_NOTBEFORE                           21   //证书有效期起始时间
#define DEC_INDEX_NOTAFTER                            22   //证书有效期截至时间
#define DEC_INDEX_SUBJECT_COUNTRYNAME                 23   //持有者国家名称
#define DEC_INDEX_SUBJECT_ORGANIZATIONNAME            24   //持有者组织名称
#define DEC_INDEX_SUBJECT_ORGANIZATIONALUNITNAME      25   //持有者部门名称
#define DEC_INDEX_SUBJECT_STATEORPROVINCENAME         26   //持有者省名
#define DEC_INDEX_SUBJECT_COMMONNAME                  27   //持有者通用名
#define DEC_INDEX_SUBJECT_LOCALITYNAME                28   //持有者所在地名
#define DEC_INDEX_SUBJECT_TITLE                        29   //持有者头衔
#define DEC_INDEX_SUBJECT_SURNAME                      30   //持有者姓
#define DEC_INDEX_SUBJECT_GIVENNAME                    31   //持有者名
#define DEC_INDEX_SUBJECT_INITIALS                     32   //持有者初名
#define DEC_INDEX_SUBJECT_EMAIL                        33   //持有者E_Mail地址
#define DEC_INDEX_SUBJECT_STREETADDRESS                34   //持有者通信地址
#define DEC_INDEX_SUBJECT_POSTALOFFICEBOX              35   //持有者信箱
#define DEC_INDEX_SUBJECT_POSTALCODE                   36   //持有者邮编
#define DEC_INDEX_SUBJECT_TELEPHONENUMBER              37   //持有者电话号码
#define DEC_INDEX_SUBJECT_FACSIMILETELEPHONENUMBER     38   //持有者传真号码
#define DEC_INDEX_DERPUBKEY                           39   //DER编码公钥
#define DEC_INDEX_USRPUBKEY                           40   //DER编码公钥(同DEC_INDEX_DERPUBKEY)
#define DEC_INDEX_ISSUER_UNIQUEID                       41   //颁发者唯一ID
#define DEC_INDEX_SUBJECT_UNIQUEID                    42   //持有者唯一ID
#define DEC_INDEX_SUBJECT_EMAILADDRESS                 43   //持有者email
#define DEC_INDEX_KEYUSAGE                            44   //密钥用法
#define DEC_INDEX_CRLDISTRIBUTIONPOINT4S1             45   //证书的CRL存取点
#define DEC_INDEX_LEGALPERSON                         52   //单位法人--> 所在单位名称
#define DEC_INDEX_BUSSINESSCODE                       53   //用于传递基础表ID
#define DEC_INDEX_TAXCODE                             54   //
#define DEC_INDEX_CLASSNUMBER                         55   //
#define DEC_INDEX_AGENCYUNIQUEID                      57   //业务受理点
#define DEC_INDEX_SAN_DNS                             58   //主题替换名,DNS
#define DEC_INDEX_SAN_SERVERIP                        59   //主题替换名,serverIP
#define DEC_INDEX_SERVEROS                            60   //serverOS
#define DEC_INDEX_USERADDRESS                         69   //
#define DEC_INDEX_ACCOUNT                             70   //设备号或服务器编号
#define DEC_INDEX_UNITCHARACTER                       71   //单位代码
#define DEC_INDEX_SUBJECTUSAGE                        72   //单位类别代码
#define DEC_INDEX_INT_CERTTYPE                        73   //证书性质(整数)
#define DEC_INDEX_CERTUSAGE                           74   //证书性质
#define DEC_INDEX_AUTHORITYKEYID                      75   //颁发机构密钥标识符
#define DEC_INDEX_SUBJECTKEYID                        76   //主题密钥标识符
#define DEC_INDEX_AUTHORITYINFOACCESS1                77   //ocsp的http或ldap访问站点URI1
#define DEC_INDEX_AUTHORITYINFOACCESS2                78   //ocsp的http或ldap访问站点URI2
#define DEC_INDEX_CRLDISTRIBUTIONPOINTS               79   //证书的CRL存取点2
#define DEC_INDEX_ISCA                                80   //
#define DEC_INDEX_IDENTIFYCARDNUMBER                  81   //1.2.86.11.7.1   中国信息安全标委会证书扩展域：身份证号
#define DEC_INDEX_INSURANCENUMBER                     82   //1.2.86.11.7.2   中国信息安全标委会证书扩展域：社会保险号
#define DEC_INDEX_ORGNAZATIONCODE                     83   //1.2.86.11.7.3   中国信息安全标委会证书扩展域：组织机构代码
#define DEC_INDEX_ICREGISTRATIONNUMBER                84   //1.2.86.11.7.4   中国信息安全标委会证书扩展域：工商注册号
#define DEC_INDEX_TAXATIONNUMEBER                     85   //1.2.86.11.7.5   中国信息安全标委会证书扩展域：税号
#define DEC_INDEX_NETSCAPECERTTYPE                    86   //
#define DEC_INDEX_ROOTSERIALNUMBER                    87   //
#define DEC_INDEX_SUBJECT_DEVICENUMBER                 88   //2.5.4.5 持有者主题SERIALNUBER
#define DEC_INDEX_SUBJECT_DESCRIPTION                  89   //2.5.4.13 持有者主题 Description
#define DEC_INDEX_PRIV_EXT_CERTUSAGE_A                90  //
#define DEC_INDEX_DC                                  91   //
#define DEC_INDEX_PRIV_EXT_LEGALPERSON                100  //所在单位名称(PRIV_EXT)
#define DEC_INDEX_PRIV_EXT_BUSINESSCODE               101  //社会保险号(PRIV_EXT)
#define DEC_INDEX_PRIV_EXT_TAXCODE                    102  //
#define DEC_INDEX_PRIV_EXT_AGENCYUNIQUEID             103  //
#define DEC_INDEX_PRIV_EXT_SERVERDNS                  104  //
#define DEC_INDEX_PRIV_EXT_SERVERIP                   105  //
#define DEC_INDEX_PRIV_EXT_SERVEROS                   106  //
#define DEC_INDEX_PRIV_EXT_USERADDRESS                107  //
#define DEC_INDEX_PRIV_EXT_ACCOUNT                    108  //注册唯一编号
#define DEC_INDEX_PRIV_EXT_UNITCHARACTER              109  //
#define DEC_INDEX_PRIV_EXT_SUBJECTUSAGE               110  //
#define DEC_INDEX_PRIV_EXT_CERTUSAGE                  111  //
#define DEC_INDEX_HTTPADDRESS                         112  //登录名
#define DEC_INDEX_CAEMAILADDRESS                      113  //caemail地址
#define DEC_INDEX_CAHTTPADDRESS                       114  //cahttp地址
#define DEC_INDEX_POLICY                              115  //
#define DEC_INDEX_GUID                                116  //GUID
#define DEC_INDEX_NAME                                117  //
#define DEC_INDEX_SUBJECT_GENERATIONQUALIFIER          118  //
#define DEC_INDEX_ISSUER_GENERATIONQUALIFIER          119  //
#define DEC_INDEX_SXCA1                               131  //陕西CA扩展1
#define DEC_INDEX_SXCA2                               132  //陕西CA扩展2
#define DEC_INDEX_EGOVIDENTIFYCODE                    141  //个人身份标识码(国标)
#define DEC_INDEX_EGOVINSURANCENUMBER                 142  //个人社会保险号(国标)
#define DEC_INDEX_EGOVORGANIZEATIONCODE               143  //企业组织机构代码(国标)
#define DEC_INDEX_EGOVICREGISTRATIONNUMBER            144  //企业工商注册号(国标)
#define DEC_INDEX_EGOVTAXATIONNUMBER                  145  //企业税号(国标)
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
#define DEC_INDEX_EGOVPAPERTYPE                       230  //个人身份标识码(国标)-证件类型
#define DEC_INDEX_EGOVPAPERCODE                       231  //个人身份标识码(国标)-证件号码
#define DEC_INDEX_SUBJECTALTNAME                      159  //使用者可选名称

#define DEC_INDEX_SUBJECT							  400	//主题
#define DEC_INDEX_ISSUER							  401	//颁发者
#define DEC_INDEX_DEREXTENSION						  500	//扩展域
#define	DEC_INDEX_AUTHORITYINFOACCESS				  501	//颁发者信息访问地址 OCSP
#define DEC_INDEX_SUBJECTKEYIDENTIFIER				  502	//主题密钥标识符
#define DEC_INDEX_AUTHORITYKEYIDENTIFIER			  503	//颁发者密钥标识符
#define DEC_INDEX_SUBJECTALTERNATIVENAME			  504	//主题备用名称
#define DEC_INDEX_BASICCONSTRAINTS					  505	//基本约束
#define DEC_INDEX_ISSUERALTERNATIVENAME				  506	//颁发者备用名称
#define DEC_INDEX_CRLNUMBER							  507	//CRL号码
#define DEC_INDEX_CRLREASON							  508	//CRL原因
#define DEC_INDEX_CERTIFICATEPOLICIES			      509	//证书策略
#define DEC_INDEX_POLICYMAPPINGS					  510	//策略映射
#define DEC_INDEX_POLICYCONSTRAINTS					  511	//策略约束
#define DEC_INDEX_SUBJECTDIRECTORYATTRIBUTES		  512	//主题目录属性
#define DEC_INDEX_NAMECONSTRAINTS					  513	//名称约束
#define DEC_INDEX_ISSUER_FACSIMILETELEPHONENUMBER	  514	//颁发者传真号码
#define DEC_INDEX_ISSUER_BUSINESSCATEGORY			  515	//颁发者商业类别
#define DEC_INDEX_SUBJECT_BUSINESSCATEGORY			  516	//使用者商业类别

#endif // !CERTINDEX
