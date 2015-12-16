#include "r2pipe.h"

R2Pipe::R2Pipe(QString filepath) {
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

QString R2Pipe::cmd(QString x) {
	Write (x + "\n");
	return Read();
}

QJsonObject R2Pipe::cmdj(QString x) {
	QString r = cmd(x);
	QJsonDocument d = QJsonDocument::fromJson(r.toUtf8());
	return d.object();
}

void R2Pipe::close() {
	if (proc != NULL) {
		proc->terminate();
	}
}
