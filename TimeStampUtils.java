package com.yucheng.smarthealthpro.utils;

import com.facebook.internal.security.CertificateUtil;
import com.google.android.material.timepicker.TimeModel;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;

/* loaded from: classes3.dex */
public class TimeStampUtils {
    public static String parseHour(int i2) {
        int i3 = i2 - (i2 % 60);
        int i4 = (i3 - (((i3 / 60) % 60) * 60)) / 3600;
        if (i4 >= 10) {
            return i4 + "";
        }
        return "0" + i4;
    }

    public static String parseMinute(int i2) {
        int i3 = ((i2 - (i2 % 60)) / 60) % 60;
        if (i3 >= 10) {
            return i3 + "";
        }
        return "0" + i3;
    }

    public static String parseSecond(int i2) {
        StringBuilder sb;
        StringBuilder append;
        int i3 = i2 % 60;
        int i4 = i2 / 60;
        int i5 = i4 % 60;
        int i6 = (i4 / 60) % 60;
        StringBuilder append2 = new StringBuilder().append((i6 >= 10 ? new StringBuilder() : new StringBuilder("0")).append(i6).append(CertificateUtil.DELIMITER).toString()).append((i5 >= 10 ? new StringBuilder() : new StringBuilder("0")).append(i5).append(CertificateUtil.DELIMITER).toString());
        if (i3 >= 10) {
            sb = new StringBuilder();
            append = sb.append(i3).append("");
        } else {
            sb = new StringBuilder("0");
            append = sb.append(i3);
        }
        return append2.append(append.toString()).toString();
    }

    public static String getToDay() {
        return new SimpleDateFormat(AppDateMgr.DF_YYYY_MM_DD).format(new Date());
    }

    public static Date stampForDate(Integer num) {
        return new Date(num.intValue() * 1000);
    }

    public static Date longStampForDate(long j2) {
        return new Date(j2);
    }

    public static Long getStringToTimestamp(String str, String str2) {
        long j2;
        try {
            j2 = new SimpleDateFormat(str2).parse(str).getTime();
        } catch (ParseException e2) {
            e2.printStackTrace();
            j2 = 0;
        }
        return Long.valueOf(j2);
    }

    public static String dateForString(Date date) {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(date);
    }

    public static String dateForString(Date date, String str) {
        return new SimpleDateFormat(str, Locale.getDefault()).format(date);
    }

    public static String dateForStringYearToDate(Date date) {
        return new SimpleDateFormat(AppDateMgr.DF_YYYY_MM_DD).format(date);
    }

    public static String toFormatDate(String str) {
        try {
            return new SimpleDateFormat("MM-dd").format(new SimpleDateFormat(AppDateMgr.DF_YYYY_MM_DD).parse(str));
        } catch (ParseException e2) {
            e2.printStackTrace();
            return "";
        }
    }

    public static String dateForStringYearToMonth(Date date) {
        return new SimpleDateFormat("yyyy/MM").format(date);
    }

    public static String dateForStringDate(Date date) {
        return new SimpleDateFormat("MM/dd").format(date);
    }

    public static String dateForStringMonthDate(Date date) {
        return new SimpleDateFormat("MM").format(date);
    }

    public static String dateForStringDates(Date date) {
        return new SimpleDateFormat("MM-dd").format(date);
    }

    public static String dateForStringToDate(Date date) {
        return new SimpleDateFormat(AppDateMgr.DF_HH_MM).format(date);
    }

    public static String cal(int i2) {
        int i3;
        int i4;
        int i5 = i2 % 3600;
        if (i2 > 3600) {
            i4 = i2 / 3600;
            if (i5 == 0) {
                i5 = 0;
                i3 = 0;
            } else if (i5 > 60) {
                i3 = i5 / 60;
                i5 %= 60;
                if (i5 == 0) {
                    i5 = 0;
                }
            } else {
                i3 = 0;
            }
        } else {
            int i6 = i2 / 60;
            int i7 = i2 % 60;
            i3 = i6;
            if (i7 != 0) {
                i5 = i7;
                i4 = 0;
            } else {
                i4 = 0;
                i5 = 0;
            }
        }
        return String.format(TimeModel.ZERO_LEADING_NUMBER_FORMAT, Integer.valueOf(i4)) + CertificateUtil.DELIMITER + String.format(TimeModel.ZERO_LEADING_NUMBER_FORMAT, Integer.valueOf(i3)) + CertificateUtil.DELIMITER + String.format(TimeModel.ZERO_LEADING_NUMBER_FORMAT, Integer.valueOf(i5));
    }

    public static String dateForStringToDateHHmmss(Date date) {
        return new SimpleDateFormat(AppDateMgr.DF_HH_MM_SS).format(date);
    }

    public static String dateForStringToHourDate(Date date) {
        return new SimpleDateFormat("HH").format(date);
    }

    public static Date stringForDate(String str) {
        try {
            return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(str);
        } catch (ParseException e2) {
            e2.printStackTrace();
            return null;
        }
    }

    public static Date stringForDateDay(String str) {
        try {
            return new SimpleDateFormat(AppDateMgr.DF_YYYY_MM_DD).parse(str);
        } catch (ParseException e2) {
            e2.printStackTrace();
            return null;
        }
    }

    public static long getStringToDate(String str, String str2) {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(str2);
        Date date = new Date();
        try {
            date = simpleDateFormat.parse(str);
        } catch (ParseException e2) {
            e2.printStackTrace();
        }
        return date.getTime();
    }

    public static Integer dateForStamp(Date date) {
        return Integer.valueOf((int) (date.getTime() / 1000));
    }

    public long getDistanceTime(long j2, long j3) {
        long j4 = j2 < j3 ? j3 - j2 : j2 - j3;
        long j5 = (j4 / org.apache.commons.lang3.time.DateUtils.MILLIS_PER_DAY) * 24;
        long j6 = (j4 / org.apache.commons.lang3.time.DateUtils.MILLIS_PER_HOUR) - j5;
        long j7 = j5 * 60;
        long j8 = j6 * 60;
        return (((j4 / 1000) - (j7 * 60)) - (j8 * 60)) - ((((j4 / org.apache.commons.lang3.time.DateUtils.MILLIS_PER_MINUTE) - j7) - j8) * 60);
    }

    public static boolean isSameDate(long j2, long j3) {
        Calendar calendar = Calendar.getInstance();
        Calendar calendar2 = Calendar.getInstance();
        calendar.setTimeInMillis(j2);
        calendar2.setTimeInMillis(j3);
        return calendar.get(1) == calendar2.get(1) && calendar.get(6) == calendar2.get(6);
    }

    public static int getMinForDay(long j2) {
        GregorianCalendar gregorianCalendar = new GregorianCalendar();
        gregorianCalendar.setTimeInMillis(j2);
        return (gregorianCalendar.get(11) * 60) + gregorianCalendar.get(12);
    }

    public static int getSecondsForDay(long j2) {
        GregorianCalendar gregorianCalendar = new GregorianCalendar();
        gregorianCalendar.setTimeInMillis(j2);
        return (gregorianCalendar.get(11) * 60 * 60) + (gregorianCalendar.get(12) * 60) + gregorianCalendar.get(13);
    }
}
