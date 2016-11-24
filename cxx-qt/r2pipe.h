#include <QtNetwork>
#include <QProcess>
#include <unistd.h>

#define HAVE_R2_API 1

/* interface must be R2Pipe */

class R2Pipe {
private:
	QObject *parent;
	QProcess *proc;
	int r2p_fd[2];

	QString Read() {
		QString r = QString();
		char ch;
		if (r2p_fd[0] == -1) {
			return NULL;
		}
		while (read (r2p_fd[0], &ch, 1) == 1) {
			if (ch == 0) break;
			r += ch;
		}
		return r;
	}

	bool Write(QString cmd) {
		const char *str = (const char *)cmd.toLatin1();
		const int len = strlen (str);
		return write (r2p_fd[1], str, len + 1) != -1;
	}
public:
	R2Pipe(QString filepath = NULL);
	QString cmd(QString x);
	QJsonObject cmdj(QString x);
	void close();
};

#if HAVE_R2_API
#include <r2naked.h>

class R2PipeAPI {
private:
        void *core;
public:
	R2PipeAPI(QString filepath = NULL);
	QString cmd(QString x);
	QJsonObject cmdj(QString x);
	void close();
};
#endif
