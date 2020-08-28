#ifndef CMAINWIN_HH
#define CMAINWIN_HH

#include <QWidget>

QT_BEGIN_NAMESPACE
namespace Ui { class CMainWin; }
QT_END_NAMESPACE

class CMainWin : public QWidget
{
    Q_OBJECT

public:
    CMainWin(QWidget *parent = nullptr);
    ~CMainWin();

private slots:
    void __On_Key_Changed(const QString& key);
    void __On_Key_Enter();
    void __On_Ivec_Changed(const QString& key);
    void __On_SrcString_Changed(const QString& key);
    void __On_SrcString_Changed();
    void __On_Encrypt_Decrypt_Changed();
    void __On_StartBtn_Clicked();

private:
    bool __Check_Ready();

private:
    Ui::CMainWin *ui;
};
#endif // CMAINWIN_HH
