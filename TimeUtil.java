package com.yucheng.ycbtsdk.utils;

import java.util.Calendar;
import java.util.TimeZone;

/* loaded from: classes4.dex */
public class TimeUtil {
    public static byte[] makeBleTime() {
        Calendar calendar = Calendar.getInstance();
        int i2 = calendar.get(1);
        int i3 = calendar.get(2) + 1;
        int i4 = calendar.get(5);
        int i5 = calendar.get(7);
        return new byte[]{(byte) (i2 & 255), (byte) ((i2 >> 8) & 255), (byte) i3, (byte) i4, (byte) calendar.get(11), (byte) calendar.get(12), (byte) calendar.get(13), (byte) (i5 == 1 ? 6 : i5 - 2)};
    }

    public static byte[] makeBleTime(long j2) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(j2);
        int i2 = calendar.get(1);
        int i3 = calendar.get(2) + 1;
        int i4 = calendar.get(5);
        int i5 = calendar.get(7);
        return new byte[]{(byte) (i2 & 255), (byte) ((i2 >> 8) & 255), (byte) i3, (byte) i4, (byte) calendar.get(11), (byte) calendar.get(12), (byte) calendar.get(13), (byte) (i5 == 1 ? 6 : i5 - 2)};
    }

    public static byte[] makeBleTimeZone() {
        Calendar calendar = Calendar.getInstance();
        long offset = TimeZone.getDefault().getOffset(System.currentTimeMillis());
        long timeInMillis = calendar.getTimeInMillis() / 1000;
        YCBTLog.e("时区=" + (((offset / 1000) / 60) / 60));
        return new byte[]{(byte) (timeInMillis & 255), (byte) ((timeInMillis >> 8) & 255), (byte) ((timeInMillis >> 16) & 255), (byte) ((timeInMillis >> 24) & 255), (byte) ((timeInMillis >> 32) & 255), (byte) ((timeInMillis >> 40) & 255), (byte) ((timeInMillis >> 48) & 255), (byte) ((timeInMillis >> 56) & 255), (byte) (r2 & 255)};
    }
}
