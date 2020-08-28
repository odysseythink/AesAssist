#include "main_win.hh"
#include "ui_main_win.h"
#include <QDebug>
#include <QMessageBox>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <QByteArray>
#include "version.hh"

using namespace std;

static string __Encrypt_Str(string key, string iv, string src){
    CryptoPP::byte* keyBuf;
    CryptoPP::byte ivBuf[CryptoPP::AES::BLOCKSIZE];
    uint32_t keyLen = 32;
    if(key.size() <= 16){
        keyLen = 16;
    } else if(key.size() <= 24){
        keyLen = 24;
    } else if(key.size() <= 32){
        keyLen = 32;
    }
    keyBuf = (CryptoPP::byte*)malloc(keyLen);
    memset(keyBuf, 0x00, keyLen);
    memset(ivBuf, 0x00, CryptoPP::AES::BLOCKSIZE);
    memcpy(keyBuf, key.c_str(), key.size());
    memcpy(ivBuf, iv.c_str(), iv.size());

    string ciphertext;
    string decryptedtext;

    //
    // Create Cipher Text
    //
    CryptoPP::AES::Encryption aesEncryption(keyBuf, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, ivBuf );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( src.c_str() ), src.length() );
    stfEncryptor.MessageEnd();
    return ciphertext;
}

static string __Decrypt_Str(string key, string iv, string src){
    CryptoPP::byte* keyBuf;
    CryptoPP::byte ivBuf[CryptoPP::AES::BLOCKSIZE];
    uint32_t keyLen = 32;
    if(key.size() <= 16){
        keyLen = 16;
    } else if(key.size() <= 24){
        keyLen = 24;
    } else if(key.size() <= 32){
        keyLen = 32;
    }
    keyBuf = (CryptoPP::byte*)malloc(keyLen);
    memset(keyBuf, 0x00, keyLen);
    memset(ivBuf, 0x00, CryptoPP::AES::BLOCKSIZE);
    memcpy(keyBuf, key.c_str(), key.size());
    memcpy(ivBuf, iv.c_str(), iv.size());

    string decryptedtext;

    //
    // Decrypt
    //
    CryptoPP::AES::Decryption aesDecryption(keyBuf, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, ivBuf );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedtext ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( src.c_str() ), src.size() );
    stfDecryptor.MessageEnd();

    return decryptedtext;
}

CMainWin::CMainWin(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::CMainWin)
{
    ui->setupUi(this);
    setWindowTitle(QString("%1 v%2").arg(APP_NAME).arg(APP_VERSION));
}

CMainWin::~CMainWin()
{
    delete ui;
}

void CMainWin::__On_Key_Changed(const QString &key)
{
    if(__Check_Ready()){
        ui->m_iStartBtn->setEnabled(true);
    } else {
        ui->m_iStartBtn->setEnabled(false);
    }
}

void CMainWin::__On_Key_Enter()
{
    if(ui->m_iKeyLenghtEdit->currentText() == "AES128"){
        if(ui->m_iKeyEdit->text().size() > 16){
            QMessageBox::critical(this, tr("key长度不对"), tr("AES128模式下key的长度为16个字节，请仔细核对"));
        }
    } else if(ui->m_iKeyLenghtEdit->currentText() == "AES192"){
        if(ui->m_iKeyEdit->text().size() > 24){
            QMessageBox::critical(this, tr("key长度不对"), tr("AES192模式下key的长度为24个字节，请仔细核对"));
        }
    } else if(ui->m_iKeyLenghtEdit->currentText() == "AES256"){
        if(ui->m_iKeyEdit->text().size() > 32){
            QMessageBox::critical(this, tr("key长度不对"), tr("AES256模式下key的长度为32个字节，请仔细核对"));
        }
    }

    if(__Check_Ready()){
        ui->m_iStartBtn->setEnabled(true);
    } else {
        ui->m_iStartBtn->setEnabled(false);
    }
}

void CMainWin::__On_Ivec_Changed(const QString &key)
{
    if(ui->m_iIvecEdit->text().size() > CryptoPP::AES::BLOCKSIZE){
        QMessageBox::critical(this, tr("iv长度不对"), tr("iv的长度不能超过")+QString::number(CryptoPP::AES::BLOCKSIZE));
    }

    if(__Check_Ready()){
        ui->m_iStartBtn->setEnabled(true);
    } else {
        ui->m_iStartBtn->setEnabled(false);
    }
}

void CMainWin::__On_SrcString_Changed(const QString& key)
{
    if(__Check_Ready()){
        ui->m_iStartBtn->setEnabled(true);
    } else {
        ui->m_iStartBtn->setEnabled(false);
    }
}

void CMainWin::__On_SrcString_Changed()
{
//    if(ui->m_iDecryptRBtn->isChecked()){
//        if(ui->m_iSrcInfoEdit->text().size() != 128){
//            QMessageBox::critical(this, tr("解密参数不对"), tr("解密的时候解密字符串长度必须为64"));
//        }
//    }

    if(__Check_Ready()){
        ui->m_iStartBtn->setEnabled(true);
    } else {
        ui->m_iStartBtn->setEnabled(false);
    }
}

void CMainWin::__On_Encrypt_Decrypt_Changed()
{
    if(ui->m_iEncryptRBtn->isChecked()){
//        if(ui->m_iSrcInfoEdit->validator() != nullptr){
//            delete  ui->m_iSrcInfoEdit->validator();
//        }
//        ui->m_iSrcInfoEdit->setValidator(nullptr);
        ui->m_iDstInfoLbl->setText(tr("加密字符串："));
        ui->m_iStartBtn->setText(tr("加密"));
        ui->m_iDstInfoEdit->clear();
        ui->m_iSrcInfoEdit->clear();
    } else {
//        QRegExp rx("[A-fa-f0-9]{1,128}");
//        QRegExpValidator *pReg = new QRegExpValidator(rx, this);
//        ui->m_iSrcInfoEdit->setValidator(pReg);
        ui->m_iDstInfoLbl->setText(tr("解密字符串："));
        ui->m_iStartBtn->setText(tr("解密"));
        ui->m_iDstInfoEdit->clear();
        ui->m_iSrcInfoEdit->clear();
    }
    if(__Check_Ready()){
        ui->m_iStartBtn->setEnabled(true);
    } else {
        ui->m_iStartBtn->setEnabled(false);
    }
}

void CMainWin::__On_StartBtn_Clicked()
{
    if(ui->m_iEncryptRBtn->isChecked()){ // 加密
        string out = __Encrypt_Str(ui->m_iKeyEdit->text().toStdString(), ui->m_iIvecEdit->text().toStdString(), ui->m_iSrcInfoEdit->text().toStdString());
        qDebug() << "encrypt string len=" << out.size();
        QByteArray outData = QByteArray::fromStdString(out);
//        QString dstStr;
//        for(uint32_t i = 0; i < out.size(); i++) {
//            QString hexStr = QString::asprintf("%02x", (0xFF & static_cast<CryptoPP::byte>(out[i])));
//            dstStr += hexStr;
//        }
        qDebug() << "encrypt string:" <<outData.toHex();
        ui->m_iDstInfoEdit->setText(outData.toBase64());
    } else { // 解密
        QByteArray srcData = QByteArray::fromBase64(ui->m_iSrcInfoEdit->text().toLocal8Bit(), QByteArray::Base64Encoding);
        qDebug() << "Decrypt src string:" <<srcData.toHex();
        string src = srcData.toStdString();
        qDebug() << "Decrypt src string len=" << src.length();
        string out = __Decrypt_Str(ui->m_iKeyEdit->text().toStdString(), ui->m_iIvecEdit->text().toStdString(), src);
        qDebug() << "Decrypt string len=" << out.size();
        ui->m_iDstInfoEdit->setText(QString::fromStdString(out));
    }
}

bool CMainWin::__Check_Ready()
{
    if(ui->m_iKeyEdit->text() == ""){
        return false;
    } else {
        if(ui->m_iKeyLenghtEdit->currentText() == "AES128"){
            if(ui->m_iKeyEdit->text().size() > 16){
                return false;
            }
        } else if(ui->m_iKeyLenghtEdit->currentText() == "AES192"){
            if(ui->m_iKeyEdit->text().size() > 24){
                return false;
            }
        } else if(ui->m_iKeyLenghtEdit->currentText() == "AES256"){
            if(ui->m_iKeyEdit->text().size() > 32){
                return false;
            }
        } else {
            return false;
        }
    }
    if(ui->m_iIvecEdit->text() == "" || ui->m_iIvecEdit->text().size() > CryptoPP::AES::BLOCKSIZE){
        return false;
    }
    if(ui->m_iSrcInfoEdit->text() == ""){
        return false;
    }
//    if(ui->m_iDecryptRBtn->isChecked()){
//        if(ui->m_iSrcInfoEdit->text().size() != 128){
//            return false;
//        }
//    }
    return true;
}

