#include <QtNetwork>
#include <QProcess>
#include <unistd.h>


class R2Pipe {
private:
	QObject *parent;
	QProcess *proc;
	int r2p_fd[2];

	QString Read() {
		QString r = QString();
		char ch;
		if (r2p_fd[0] == -1)
			return NULL;
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
	R2Pipe(QString filepath = NULL) {
		parent = NULL;
		r2p_fd[0] = r2p_fd[1] = -1;
		if (filepath.isEmpty()) {
			QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
			proc = NULL;
			QString r2p_in = env.value("R2PIPE_IN");
			QString r2p_out = env.value("R2PIPE_OUT");
			if (r2p_in.isEmpty() || r2p_out.isEmpty()) {
				throw QString("Cannot find R2PIPE_IN or R2PIPE_OUT environment");
			}
			r2p_fd[0] = r2p_in.toInt();
			r2p_fd[1] = r2p_out.toInt();
			// Check R2PIPE_IN and R2PIPE_OUT env vars
		} else {
			proc = new QProcess(parent);
			QStringList args;
			args << "-q0" << filepath;
			proc->start("/usr/bin/r2", args);
			// TODO: support spawn method
		}
	}

	QString cmd(QString x) {
		Write (x + "\n");
		return Read();
	}

	QJsonObject cmdj(QString x) {
		QString r = cmd(x);
		QJsonDocument d = QJsonDocument::fromJson(r.toUtf8());
		return d.object();
	}

	void close() {
		if (proc != NULL) {
			proc->terminate();
		}
	}
};

static QTextStream& cout() {
    static QTextStream ts(stdout);
    return ts;
}

int main() {
	R2Pipe *r2;
	try {
		r2 = new R2Pipe();
	} catch (QString err) {
		cout() << err << "\n";
		r2 = new R2Pipe("/bin/ls");
	}
	cout() << r2->cmd ("?e hello world");
	cout() << r2->cmd ("x");
	cout() << r2->cmd ("pd 3");
	r2->close();
	return 0;
}
