package com.yucheng.smarthealthpro.utils;

import com.facebook.internal.security.CertificateUtil;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.TimeZone;
import org.apache.commons.lang3.time.TimeZones;

/* loaded from: classes3.dex */
public class TimeZoneUtils {
    public static String getTimeZone() {
        String format = new SimpleDateFormat("Z").format(Calendar.getInstance(TimeZone.getTimeZone(TimeZones.GMT_ID), Locale.getDefault()).getTime());
        return "" + format.substring(0, 3) + CertificateUtil.DELIMITER + format.substring(3, 5);
    }

    public static String getTimeZoneOffset() {
        int offset = ((new GregorianCalendar().getTimeZone().getOffset(System.currentTimeMillis()) / 1000) / 60) / 60;
        return (offset > 0 ? new StringBuilder("+") : new StringBuilder("")).append(offset).toString();
    }
}
