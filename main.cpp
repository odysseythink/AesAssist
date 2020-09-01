#include "main_win.hh"

#include <QDebug>
#include <QApplication>
#include <glog/logging.h>
#include <io.h>
#include <direct.h>
#include "version.hh"

static void __Log_Init(const char* appname){
    char currentPath[1024] = {0};
    char logPath[1024] = {0};

    _getcwd(currentPath, sizeof(currentPath));
    sprintf(logPath, "%s\\logs\\", currentPath);
    if(_access(logPath, F_OK) != 0){
        _mkdir(logPath);
    }
    qDebug() << "logPath=" << logPath;
    FLAGS_colorlogtostderr = true;
    FLAGS_alsologtostderr = true;
    std::string logPathString = logPath;
    std::string logfileprefix = logPathString + "fatal-";
    google::SetLogDestination(google::GLOG_FATAL, logfileprefix.c_str());
    logfileprefix = logPathString + "error-";
    google::SetLogDestination(google::GLOG_ERROR, logfileprefix.c_str());
    logfileprefix = logPathString + "warning-";
    google::SetLogDestination(google::GLOG_WARNING, logfileprefix.c_str());
    logfileprefix = logPathString + "info-";
    google::SetLogDestination(google::GLOG_INFO, logfileprefix.c_str());
    google::InitGoogleLogging(appname);
    google::SetLogFilenameExtension(".log");
    FLAGS_logbufsecs = 0;
}


int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    __Log_Init(argv[0]);
    LOG(INFO) << APP_NAME << "-v" << APP_VERSION << " running......";
    CMainWin w;
    w.show();
    return a.exec();
}
