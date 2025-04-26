package com.yucheng.smarthealthpro.utils;

import androidx.exifinterface.media.ExifInterface;
import com.facebook.internal.security.CertificateUtil;
import com.google.firebase.crashlytics.buildtools.reloc.org.apache.commons.cli.HelpFormatter;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;

/* loaded from: classes3.dex */
public class YearToDayListUtils {
    public static ArrayList<String> getPastByMonthDayArray(String str, int i2) {
        ArrayList<String> arrayList = new ArrayList<>();
        Iterator<String> it2 = getPastStringArray(str, i2).iterator();
        while (it2.hasNext()) {
            arrayList.add(TimeStampUtils.dateForStringDates(TimeStampUtils.stringForDateDay(it2.next())));
        }
        return arrayList;
    }

    public static ArrayList<String> getPastStringArray(String str, int i2) {
        try {
            return getPastStringArrayByDate(new SimpleDateFormat(AppDateMgr.DF_YYYY_MM_DD).parse(str), i2);
        } catch (ParseException e2) {
            e2.printStackTrace();
            return new ArrayList<>();
        }
    }

    public static ArrayList<String> getPastStringArrayByDate(Date date, int i2) {
        ArrayList<String> arrayList = new ArrayList<>();
        while (i2 >= 0) {
            arrayList.add(getPastDateString(i2, date));
            i2--;
        }
        return arrayList;
    }

    public static String getPastDateString(int i2, Date date) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.set(5, calendar.get(5) - i2);
        return new SimpleDateFormat(AppDateMgr.DF_YYYY_MM_DD).format(calendar.getTime());
    }

    public static Date getPastDate(int i2, Date date) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.set(5, calendar.get(5) - i2);
        return calendar.getTime();
    }

    public static int getMonthLastDay(int i2, int i3) {
        Calendar calendar = Calendar.getInstance();
        calendar.set(1, i2);
        calendar.set(2, i3 - 1);
        calendar.set(5, 1);
        calendar.roll(5, -1);
        return calendar.get(5);
    }

    public static int getCurrMonthDay() {
        Calendar calendar = Calendar.getInstance();
        calendar.set(5, 1);
        calendar.roll(5, -1);
        return calendar.get(5);
    }

    public static int getHourFromDateString(String str) {
        SimpleDateFormat simpleDateFormat;
        try {
            if (str.contains(ExifInterface.GPS_DIRECTION_TRUE)) {
                simpleDateFormat = new SimpleDateFormat("yyyyMMdd'T'HH:mm:ss");
            } else if (str.contains(HelpFormatter.DEFAULT_OPT_PREFIX) && str.contains(CertificateUtil.DELIMITER)) {
                simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            } else {
                if (!str.contains(CertificateUtil.DELIMITER)) {
                    return -1;
                }
                simpleDateFormat = new SimpleDateFormat(AppDateMgr.DF_HH_MM_SS);
            }
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(simpleDateFormat.parse(str));
            return calendar.get(11);
        } catch (Exception e2) {
            e2.printStackTrace();
            return -1;
        }
    }

    public static int[] getTimeFromDateString(String str) {
        SimpleDateFormat simpleDateFormat;
        int[] iArr = new int[3];
        try {
            if (str.contains(ExifInterface.GPS_DIRECTION_TRUE)) {
                simpleDateFormat = new SimpleDateFormat("yyyyMMdd'T'HH:mm:ss");
            } else if (str.contains(HelpFormatter.DEFAULT_OPT_PREFIX) && str.contains(CertificateUtil.DELIMITER)) {
                simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            } else {
                if (!str.contains(CertificateUtil.DELIMITER)) {
                    return null;
                }
                simpleDateFormat = new SimpleDateFormat(AppDateMgr.DF_HH_MM_SS);
            }
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(simpleDateFormat.parse(str));
            iArr[0] = calendar.get(11);
            iArr[1] = calendar.get(12);
            iArr[2] = calendar.get(13);
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        return iArr;
    }

    public static int getHourFromTimeStamp(long j2) {
        try {
            Date date = new Date();
            date.setTime(j2);
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(date);
            return calendar.get(11);
        } catch (Exception e2) {
            e2.printStackTrace();
            return -1;
        }
    }

    public static String getStringDateFromMonth(int i2) {
        String str = i2 + "";
        try {
            Calendar calendar = Calendar.getInstance();
            calendar.add(2, i2 - (calendar.get(2) + 1));
            return new SimpleDateFormat("yyyy-MM").format(calendar.getTime());
        } catch (Exception e2) {
            e2.printStackTrace();
            return str;
        }
    }

    public static ArrayList<String> getPostStringDateFromMonth(int i2) {
        ArrayList<String> arrayList = new ArrayList<>();
        for (int i3 = i2 - 1; i3 >= 0; i3--) {
            try {
                Calendar calendar = Calendar.getInstance();
                calendar.get(2);
                calendar.add(2, -i3);
                arrayList.add(new SimpleDateFormat("yyyy/MM").format(calendar.getTime()));
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        return arrayList;
    }

    public static boolean isMidDate(Date date, String str, Date date2) {
        try {
            Date parse = new SimpleDateFormat(AppDateMgr.DF_YYYY_MM_DD).parse(str);
            if (parse.before(date2)) {
                return parse.after(date);
            }
            return false;
        } catch (Exception e2) {
            e2.printStackTrace();
            return false;
        }
    }

    public static int getAge(String str) {
        try {
            Calendar calendar = Calendar.getInstance();
            int i2 = calendar.get(1);
            calendar.setTime(new SimpleDateFormat(AppDateMgr.DF_YYYY_MM_DD).parse(str));
            return i2 - calendar.get(1);
        } catch (Exception e2) {
            e2.printStackTrace();
            return 0;
        }
    }

    public static String subYear(int i2) {
        try {
            Calendar calendar = Calendar.getInstance();
            calendar.add(1, -i2);
            return new SimpleDateFormat(AppDateMgr.DF_YYYY_MM_DD).format(calendar.getTime());
        } catch (Exception e2) {
            e2.printStackTrace();
            return "";
        }
    }
}
