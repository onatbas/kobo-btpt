#pragma once

#include <linux/input.h>


struct btpt_event {
	QString method = "";
	struct input_event event;
	QString shared_instance = "";
	QStringList params;

	 QString toString() const {
        // Convert your struct to a string uniquely representing its contents
        QString eventString = QString::number(event.type) + "_" +
                              QString::number(event.code) + "_" +
                              QString::number(event.value);
        return eventString + "_" + shared_instance + "_" + params.size();
    }
};