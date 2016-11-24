#include "r2pipe.h"
#if HAVE_R2_API

R2PipeAPI::R2PipeAPI(QString filepath) {
	this->core = r_core_new ();
	if (filepath != NULL) {
		this->cmd(QString("\"o %1\"").arg(filepath));
	}
}

QString R2PipeAPI::cmd(const QString str) {
	std::string tmpstr = str.toStdString();
	const char* cmd = tmpstr.c_str();
	char *res = r_core_cmd_str (this->core, cmd);
	QString o = (res && *res)? QString::fromUtf8(res): QString();
	free (res);
	return o;
}

/* Can be implemented in R2Pipe API */
QJsonObject R2PipeAPI::cmdj(QString x) {
	QString r = cmd(x);
	QJsonDocument d = QJsonDocument::fromJson(r.toUtf8());
	return d.object();
}

void R2PipeAPI::close() {
	r_core_free (this->core);
}

#endif
