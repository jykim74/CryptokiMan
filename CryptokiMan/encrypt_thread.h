#ifndef ENCRYPTTHREAD_H
#define ENCRYPTTHREAD_H

#include <QThread>

class EncryptThread : public QThread
{
    Q_OBJECT
public:
    EncryptThread();
    ~EncryptThread();

    void setSession( long uSession );
    void setSrcFile( const QString strSrcFile );
    void setDstFile( const QString strDstFile );

signals:
    void taskFinished();
    void taskUpdate( int nUpdate );

protected:
    void run() override;
    long session_;
    QString src_file_;
    QString dst_file_;
};

#endif // ENCRYPTTHREAD_H
