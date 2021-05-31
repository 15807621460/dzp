// Adds a prefix to the titles of HTML pages.
//

#include "stdafx.h"
#include <crtdbg.h>

#include "ProtocolFilters.h"
#include "PFEventsDefault.h"
#include "multipart_parser.h"

#include <QCryptographicHash>
#include <QCoreApplication>
#include <QTemporaryFile>
#pragma comment(lib,"ws2_32.lib")

using namespace nfapi;
using namespace ProtocolFilters;

// Change this string after renaming and registering the driver under different name
#define NFDRIVER_NAME "netfilter2"

std::string g_titlePrefix;

class MultipartConsumer
{
public:
    MultipartConsumer(const std::string& boundary)
    {
        memset(&m_callbacks, 0, sizeof(multipart_parser_settings));

        printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>start MultipartConsumer boundary = %s <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< \n", boundary.c_str());

        m_callbacks.on_header_field = ReadHeaderName;
        m_callbacks.on_header_value = ReadHeaderValue;
        m_callbacks.on_part_data = ReadPartData;
        m_callbacks.get_now_pos = GetNowPos;
        m_parser = multipart_parser_init(boundary.c_str(), &m_callbacks);
        multipart_parser_set_data(m_parser, this);
    }

    ~MultipartConsumer()
    {
        multipart_parser_free(m_parser);
    }

    int CountHeaders(char *pBody, int nLen)
    {
        printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>start multipart_parser_execute<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< \n");
        size_t Ret = multipart_parser_execute(m_parser, pBody, nLen);
        printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>start multipart_parser_execute Ret : %d<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< \n", Ret);
        return m_headers;
    }

    std::string m_strDataArry;
    int m_nDataStartPos = 0;
    int m_nDataLen = 0;
    int m_nFileSize = 0;
    bool m_bIsFindFileSize = false;
    bool m_bIsFindFile = false;

    std::list<std::tuple<std::string, std::string, std::string> > m_BoundaryList;

private:
    static int ReadHeaderName(multipart_parser* p, size_t pos, const char *at, size_t length)
    {
        //表单名
        MultipartConsumer* me = (MultipartConsumer*)multipart_parser_get_data(p);
        me->m_headers++;

        std::string strTemp;
        strTemp.append(at, length);
        if (strTemp.find("Content-Type") != std::string::npos)
        {
            me->m_bIsFindFile = true;
        }

        me->m_BoundaryList.push_back(std::make_tuple(strTemp, "", ""));

        printf("ReadHeaderName >>>>>>>>>>>>> %.*s \n", length, at);
        return 0;
    }

    static int ReadHeaderValue(multipart_parser* p, size_t pos, const char *at, size_t length)
    {
        //表单字段
        MultipartConsumer* me = (MultipartConsumer*)multipart_parser_get_data(p);


        std::string strTemp;
        strTemp.append(at, length);
        if (strTemp.find("name=\"size\"") != std::string::npos)
        {
            me->m_bIsFindFileSize = true;
        }

        std::get<1>(me->m_BoundaryList.back()) = strTemp;

        printf("ReadHeaderValue >>>>>>>>>>>>> %.*s \n", length, at);
        return 0;
    }

    static int ReadPartData(multipart_parser* p, size_t pos, const char *at, size_t length)
    {
        //字段值

        MultipartConsumer* me = (MultipartConsumer*)multipart_parser_get_data(p);

        if(me->m_bIsFindFileSize)
        {
            std::string strSize;
            strSize.append(at, length);
            me->m_bIsFindFileSize = false;
            me->m_nFileSize = atoi(strSize.c_str());
        }

        if (me->m_bIsFindFile)
        {
            static bool bFirstIn = true;
            if (bFirstIn)
            {
                bFirstIn = false;
                me->m_nDataStartPos = pos;
                printf("GetNowPos >>>>>>>>>>>>> %d \n", pos);
            }
            me->m_nDataLen += length;
            //me->m_strDataArry.append(at, length);
        }

        std::get<2>(me->m_BoundaryList.back()).append(at, length);

        return 0;
    }

    static int GetNowPos(multipart_parser* p, int npos)
    {
        MultipartConsumer* me = (MultipartConsumer*)multipart_parser_get_data(p);

        return 0;
    }


    multipart_parser* m_parser;
    multipart_parser_settings m_callbacks;
    int m_headers;
};

typedef struct FileHttpData  //每个数据块协议数据缓存
{
    PFObject *pHttpObj;
    QByteArray qByteHttpStatus;
    QByteArray qByteHttpHeader;
    QByteArray qByteHttpBodyWithoutFile;
    size_t nFileStartPos;
    size_t nFileLen;//当前大小
    bool bHasFile;//是否有附件
    FileHttpData()
    {
        pHttpObj = nullptr;
        bHasFile = true;
        nFileStartPos = 0;
        nFileLen = 0;
    }

} FILEHTTPDATA, *PFILEHTTPDATA;

//储存http包
typedef struct FileCatch
{
    nfapi::ENDPOINT_ID id;
    QString qTempFilePath;//文件缓存路径
    QString qstrUploadID;//上传文件的唯一标识，多POST
    int nFileID;//多POST文件块ID
    std::vector<PFILEHTTPDATA> vtHttpData;
    size_t nFileAllLen;//文件总大小
    FileCatch()
    {
        nFileAllLen = 0;
    }
    ~FileCatch()
    {
        for(auto itor : vtHttpData)
        {
            delete itor;
        }
    }

} FILECATCH, *PFILECATCH;

class HttpFilter : public PFEventsDefault
{

private:
    std::map<QString, PFILECATCH> m_mapFileCatch;

public:
    HttpFilter()
    {
    }

    virtual void tcpConnected(nfapi::ENDPOINT_ID id, nfapi::PNF_TCP_CONN_INFO pConnInfo)
    {
        if (pConnInfo->direction == NF_D_OUT)
        {
            pf_addFilter(id, FT_PROXY, FF_READ_ONLY_IN | FF_READ_ONLY_OUT);
            pf_addFilter(id, FT_SSL, FF_SSL_INDICATE_HANDSHAKE_REQUESTS | FF_SSL_VERIFY | FF_SSL_TLS_AUTO);
            pf_addFilter(id, FT_HTTP, FF_HTTP_BLOCK_SPDY);
        }
    }

    bool SendToLocal(nfapi::ENDPOINT_ID id, QByteArray &byte)
    {
        bool bSuc = false;
        PFObject *newObj = PFObject_create(OT_RAW_INCOMING, 1);
        if (newObj)
        {
            PFStream *pIn = newObj->getStream(0);
            if (pIn)
            {
                pIn->write(byte.data(), byte.size());
                bSuc = pf_postObject(id, newObj);
            }
            newObj->free();
        }
        return bSuc;
    }

    bool SendToRemove(nfapi::ENDPOINT_ID id, QByteArray &byte)
    {
        bool bSuc = false;
        PFObject *newObj = PFObject_create(OT_RAW_OUTGOING, 1);
        if (newObj)
        {
            PFStream *pOut = newObj->getStream(0);
            if (pOut)
            {
                pOut->write(byte.data(), byte.size());
                bSuc = pf_postObject(id, newObj);
            }
            newObj->free();
        }
        return bSuc;
    }

    void SendFileCatch(nfapi::ENDPOINT_ID id, PFILECATCH pFileCatch)
    {
        if(pFileCatch)
        {
            QFile qFile(pFileCatch->qTempFilePath);
            for(auto itor : pFileCatch->vtHttpData)
            {
                if(itor->bHasFile == false)
                {
                    QByteArray qSendData;
                    qSendData.resize(itor->qByteHttpStatus.size() + itor->qByteHttpHeader.size() + itor->qByteHttpBodyWithoutFile.size());
                    qSendData.clear();
                    qSendData.append(itor->qByteHttpStatus);
                    qSendData.append(itor->qByteHttpHeader);
                    qSendData.append(itor->qByteHttpBodyWithoutFile);
                    SendToRemove(id, qSendData);

                    printf(">>>>>>>>>>>>>>>>>>>> Send bHasFile == false : \n%s\n", qSendData.toStdString().c_str());
                    continue;
                }

                if(qFile.open(QIODevice::ReadOnly))
                {
                    printf(">>>>>>>>>>>>>>>>>>>> Read File \n");
                    QByteArray qFileData;
                    qFileData = qFile.read(itor->nFileLen);
                    printf(">>>>>>>>>>>>>>>>>>>> Read File : \n%d\n", qFileData.size());

                    itor->qByteHttpBodyWithoutFile.insert(itor->nFileStartPos, qFileData);

                    QByteArray qSendData;
                    qSendData.resize(itor->qByteHttpStatus.size() + itor->qByteHttpHeader.size() + itor->qByteHttpBodyWithoutFile.size());
                    qSendData.clear();
                    qSendData.append(itor->qByteHttpStatus);
                    qSendData.append(itor->qByteHttpHeader);
                    qSendData.append(itor->qByteHttpBodyWithoutFile);
                    SendToRemove(id, qSendData);
                }
            }
        }
    }

    void SendOkToRemove(nfapi::ENDPOINT_ID id, std::map<QString, QString> &mapHeader)
    {
        PFObject * newObj = PFObject_create(OT_HTTP_RESPONSE, 2);

        if (!newObj)
            return;

        const char status[] = "HTTP/1.1 200\r\n";
        PFStream * pStream;

        pStream = newObj->getStream(HS_STATUS);
        if (pStream)
        {
            pStream->write(status, sizeof(status)-1);
        }

        pStream = newObj->getStream(HS_HEADER);
        if (pStream)
        {
            PFHeader h;

            h.addField("Content-Type", "text/html;charset=UTF-8", true);
            h.addField("Connection", "keep-alive", true);
            h.addField("Keep-Alive", "timeout=200", true);

            for(auto itor = mapHeader.begin(); itor != mapHeader.end(); ++itor)
            {
                h.addField(itor->first.toStdString().c_str(), itor->second.toStdString().c_str(), true);
            }

            pf_writeHeader(pStream, &h);
            printf(">>>>>>>>>>>>>>>>>>>>>SendOKToLocal value\n%s \n", h.toString().c_str());
        }

        pf_postObject(id, newObj);

        newObj->free();
    }

    bool updateContent(PFObject * object)
    {
//		PFStream * pStream = object->getStream(HS_CONTENT);
//		char * buf;
        bool contentUpdated = false;
        return contentUpdated;
    }

    void dataAvailable(nfapi::ENDPOINT_ID id, PFObject * object)
    {
        if (object->isReadOnly())
            return;
        if ((object->getType() == OT_HTTP_REQUEST) &&
            (object->getStreamCount() == 3))
        {
            printf("================================OT_HTTP_REQUEST id : %lld===================================== \n", id);
            //获取目标服务器IP
            PNF_TCP_CONN_INFO pIpAddrInfo = new NF_TCP_CONN_INFO();
            memset(pIpAddrInfo, 0, sizeof(NF_TCP_CONN_INFO));
            NF_STATUS ret = nf_getTCPConnInfo(id, pIpAddrInfo);

            char localAddr[MAX_PATH] = "";
            char remoteAddr[MAX_PATH] = "";
            DWORD dwLen;
            sockaddr * pAddr;
            char processName[MAX_PATH] = "";

            pAddr = (sockaddr*)pIpAddrInfo->localAddress;
            dwLen = sizeof(localAddr);

            WSAAddressToStringA((LPSOCKADDR)pAddr,
                (pAddr->sa_family == AF_INET6) ? sizeof(sockaddr_in6) : sizeof(sockaddr_in),
                NULL,
                localAddr,
                &dwLen);

            pAddr = (sockaddr*)pIpAddrInfo->remoteAddress;
            dwLen = sizeof(remoteAddr);

            WSAAddressToStringA((LPSOCKADDR)pAddr,
                (pAddr->sa_family == AF_INET6) ? sizeof(sockaddr_in6) : sizeof(sockaddr_in),
                NULL,
                remoteAddr,
                &dwLen);

            printf("localAddr : %s\n", localAddr);
            printf("remoteAddr : %s\n", remoteAddr);


            PFHeader h;

            if (pf_readHeader(object->getStream(HS_HEADER), &h))
            {
                PFStream * pStatus = object->getStream(HS_STATUS);
                PFStream * pBody = object->getStream(HS_CONTENT);
                //QByteArray byteStatus;

                if(pStatus)
                {
                    char * bufStatus;
                    bufStatus = (char*)malloc((size_t)pStatus->size() + 1);
                    pStatus->read(bufStatus, (tStreamSize)pStatus->size());
                    bufStatus[pStatus->size()] = '\0';

                    QString qstrUploadID;
                    bool bHasFile = false;
                    std::string strStatus;
                    strStatus.append(bufStatus);
                    free(bufStatus);

                    if (1)
                        /*QQ:(strStatus.find("/cgi-bin/uploadunite") != std::string::npos) ||
                             ||
                            (strStatus.find("/api/create") != std::string::npos)*/
                    {
                        printf("STATUS:\n%s\n", strStatus.c_str());

                        std::string strBoundary = "--";
                        PFHeaderField * pField = h.findFirstField("Content-Type");
                        PFHeaderField * pHost = h.findFirstField("Host");
                        PFHeaderField * pOrigin = h.findFirstField("Origin");

                        if (pField)
                        {
                            std::string strConType = pField->value();
                            printf(">>>>>>>>>>>>>>>>> HEAD : \n%s \n", h.toString().c_str());
                            if (strConType.find("boundary=") != std::string::npos)
                            {
                                strBoundary += strConType.substr(strConType.find("boundary=") + strlen("boundary="), strConType.length());

                                printf(">>>>>>>>>>>>>>>>> strBoundary : %s \n", strBoundary.c_str());
                            }

                            if (pBody)
                            {
                                if (pBody->size() > 0)
                                {
                                    //printf("HS_CONTENT Len: \n %d \n", pBody->size());
                                    char * bufCONTENT;
                                    bufCONTENT = (char*)malloc((size_t)pBody->size() + 1);

                                    pBody->read(bufCONTENT, (tStreamSize)pBody->size());
                                    bufCONTENT[pBody->size()] = '\0';

                                    printf("BODY :\n%s\n", bufCONTENT);

                                    //printf(">>>>>>>>>>>>>>>>>>>>>>>>>>> Get Pos %d Len :%d \n ", obj.m_nDataStartPos, byteFile.length());
                                    free(bufCONTENT);
                                }
                            }
                        }

//                        PFObject * newObj = PFObject_create(OT_HTTP_RESPONSE, 3);
//                        if (!newObj)
//                            return;

//                        const char status[] = "HTTP/1.1 404 Not OK\r\n";
//                        const char blockHtml[] = "<html>" \
//                            "<body bgcolor=#f0f0f0><center><h1>Content blocked</h1></center></body></html>" \
//                            "<!-- - Unfortunately, Microsoft has added a clever new" \
//                            "   - 'feature' to Internet Explorer. If the text of" \
//                            "   - an error's message is 'too small', specifically" \
//                            "   - less than 512 bytes, Internet Explorer returns" \
//                            "   - its own error message. You can turn that off," \
//                            "   - but it's pretty tricky to find switch called" \
//                            "   - 'smart error messages'. That means, of course," \
//                            "   - that short error messages are censored by default." \
//                            "   - IIS always returns error messages that are long" \
//                            "   - enough to make Internet Explorer happy. The" \
//                            "   - workaround is pretty simple: pad the error" \
//                            "   - message with a big comment like this to push it" \
//                            "   - over the five hundred and twelve bytes minimum." \
//                            "   - Of course, that's exactly what you're reading" \
//                            "   - right now. -->";

//                        if(1)
//                        {
//                            PFStream * pStream;

//                            pStream = newObj->getStream(HS_STATUS);
//                            if (pStream)
//                            {
//                                pStream->write(status, sizeof(status)-1);
//                            }

//                            pStream = newObj->getStream(HS_HEADER);
//                            if (pStream)
//                            {
//                                PFHeader h;

//                                h.addField("Content-Type", "text/html", true);
//                                char szLen[100];
//                                _snprintf(szLen, sizeof(szLen), "%d", sizeof(blockHtml)-1);
//                                h.addField("Content-Length", szLen, true);
//                                h.addField("Connection", "close", true);
//                                pf_writeHeader(pStream, &h);
//                            }

//                            pStream = newObj->getStream(HS_CONTENT);
//                            if (pStream)
//                            {
//                                pStream->write(blockHtml, sizeof(blockHtml)-1);
//                            }

//                            pf_postObject(id, newObj);

//                            newObj->free();

//                            printf("=================================OT_HTTP_REQUEST FIN==================================== \n");
//                            return;
//                        }



                   }
                    if(bHasFile)
                    {
                        printf("=================================bHasFile OT_HTTP_REQUEST FIN==================================== \n");
                        return;
                    }
                }

            }
            printf("=================================OT_HTTP_REQUEST FIN==================================== \n");

        }

        if ((object->getType() == OT_HTTP_RESPONSE) &&
            (object->getStreamCount() == 3))
        {

            PFHeader h;

            if (pf_readHeader(object->getStream(HS_HEADER), &h))
            {
                PFHeaderField * pField = h.findFirstField("Content-Type");
                PFHeaderField * pFieldChunked = h.findFirstField("Transfer-Encoding");
                PFHeaderField * pFieldXEXHDR = h.findFirstField("X-EXHDR-REQUEST");
                PFStream * pBody = object->getStream(HS_CONTENT);
                PFStream * pStatus = object->getStream(HS_STATUS);
                printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>OT_HTTP_RESPONSE id : %lld>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> \n", id);
                if (pFieldXEXHDR)
                {
                    if (1)//pFieldXEXHDR->value().find("/d/ajax/fileops/uploadXHRV2") != std::string::npos /d/ajax/dirops/create
                        /*
                         * BAIDU: (pFieldXEXHDR->value().find("/rest/2.0/pcs/superfile2") != std::string::npos) ||
                                (pFieldXEXHDR->value().find("/api/precreate") != std::string::npos) ||
                                (pFieldXEXHDR->value().find("/api/create") != std::string::npos)

                        QQ: (pFieldXEXHDR->value().find("/cgi-bin/uploadunite") != std::string::npos) ||
                            (pFieldXEXHDR->value().find("/ftn_handler") != std::string::npos) ||
                            (pFieldXEXHDR->value().find("/api/create") != std::string::npos)
                        */
                    {

                        if (pStatus)
                        {
                            char * bufStatus;
                            bufStatus = (char*)malloc((size_t)pStatus->size() + 1);
                            pStatus->read(bufStatus, (tStreamSize)pStatus->size());
                            bufStatus[pStatus->size()] = '\0';

                            printf("HS_Status : \n %s", bufStatus);
                            free(bufStatus);
                        }
                        printf("HS_HEADER : %s \n", h.toString().c_str());
                        if (pBody)
                        {
                            char * bufBody;
                            bufBody = (char*)malloc((size_t)pBody->size() + 1);
                            pStatus->read(bufBody, (tStreamSize)pBody->size());
                            bufBody[pBody->size()] = '\0';
                            QTemporaryFile file;
                            file.open();
                            file.setAutoRemove(false);
                            file.write(bufBody, pBody->size());
                            printf("tempFilePath = %s \n", file.fileName().toStdString().c_str());
                            file.close();
                            printf("HS_BODY : LEN = %d;\n %s", pBody->size(), bufBody);
//                            QByteArray byte;
//                            QByteArray byteSerch("orm-data; name=\"file\";");
//                            byte.resize((size_t)pBody->size());
//                            byte.append(bufBody, pBody->size());
//                            bool bRet = byte.contains(byteSerch);
//                            printf(">>>>>>>>>>>> After Search \n");
                            free(bufBody);
//                            if(bRet)
//                            {
//                                printf(">>>>>>>>>>>> find orm-data; name=\"file\" \n");
//                                //丢弃服务器回包
//                                return;
//                            }else
//                            {
//                            }
                            //printf("return>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> \n");
                            //SendOkToRemove(id);
                            //return;
                        }

                    }
                    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>OT_HTTP_RESPONSE FIN>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> \n");
                }

                if (pField)
                {


                    if (pField->value().find("text/html") == -1)
                    {

                        pf_postObject(id, object);
                        return;
                    }


                }
            }
            updateContent(object);
        }

        pf_postObject(id, object);
    }

    PF_DATA_PART_CHECK_RESULT
    dataPartAvailable(nfapi::ENDPOINT_ID id, PFObject * object)
    {
        if (object->getType() == OT_SSL_HANDSHAKE_OUTGOING)
        {
            PFStream * pStream = object->getStream(0);
            char * buf;
            PF_DATA_PART_CHECK_RESULT res = DPCR_FILTER;

            if (pStream && pStream->size() > 0)
            {
                buf = (char*)malloc((size_t)pStream->size() + 1);
                if (buf)
                {
                    pStream->read(buf, (tStreamSize)pStream->size());
                    buf[pStream->size()] = '\0';

                    if (strcmp(buf, "get.adobe.com") == 0)
                    {
                        res = DPCR_BYPASS;
                    }

                    free(buf);
                }
            }
            return res;
        }

        //if (object->getType() == OT_HTTP_RESPONSE)
        //{
        //	PFHeader h;

        //	if (pf_readHeader(object->getStream(HS_HEADER), &h))
        //	{
        //		PFHeaderField * pField = h.findFirstField("Content-Type");
        //		if (pField)
        //		{
        //			if (pField->value().find("text/html") != -1)
        //			{
        //				if (updateContent(object))
        //				{
        //					return DPCR_UPDATE_AND_BYPASS;
        //				} else
        //				{
        //					//等待更多数据
        //					return DPCR_MORE_DATA_REQUIRED;
        //				}
        //			}
        //		}
        //	}
        //}

        //return DPCR_BYPASS;
        return DPCR_FILTER;
    }
};

int main(int argc, char* argv[])
{
    QCoreApplication a(argc, argv);
    NF_RULE rule;

    if (argc < 2)
    {
        printf("Usage: PFHttpContentFilter <string>\n" \
            "<string> : add this to titles of HTML pages\n");
        return -1;
    }

    g_titlePrefix = argv[1];
    g_titlePrefix += " ";

#ifdef _DEBUG
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    _CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_DEBUG);
#endif

    nf_adjustProcessPriviledges();

//	nf_setOptions(0, 0);

    printf("Press any key to stop...\n\n");

    HttpFilter f;

    if (!pf_init(&f, L"c:\\netfilter2"))
    {
        printf("Failed to initialize protocol filter");
        return -1;
    }

//	pf_setExceptionsTimeout(EXC_GENERIC, 30);
//	pf_setExceptionsTimeout(EXC_TLS, 30);
//	pf_setExceptionsTimeout(EXC_CERT_REVOKED, 30);

    pf_setRootSSLCertSubject("Sample CA");

    // Initialize the library and start filtering thread
    if (nf_init(NFDRIVER_NAME, pf_getNFEventHandler()) != NF_STATUS_SUCCESS)
    {
        printf("Failed to connect to driver");
        return -1;
    }

    // Filter all TCP connections
    memset(&rule, 0, sizeof(rule));
    rule.direction = NF_D_OUT;
    rule.protocol = IPPROTO_TCP;
    rule.filteringFlag = NF_FILTER;
    nf_addRule(&rule, TRUE);

    // Block QUIC
    rule.direction = NF_D_BOTH;

    rule.protocol = IPPROTO_UDP;
    rule.remotePort = ntohs(80);
    rule.filteringFlag = NF_BLOCK;
    nf_addRule(&rule, TRUE);

    rule.protocol = IPPROTO_UDP;
    rule.remotePort = ntohs(443);
    rule.filteringFlag = NF_BLOCK;
    nf_addRule(&rule, TRUE);

    // Wait for any key
    getchar();

    // Free the libraries
    nf_free();
    pf_free();

    return 0;
}

