package com.yucheng.ycbtsdk.core;

import com.yucheng.ycbtsdk.response.BleDataResponse;

/* loaded from: classes4.dex */
public class YCSendBean implements Comparable<YCSendBean> {
    private static int SENDSN = 1;
    private static final int YCMAXLEN = 100000;
    public int collectDigits = 16;
    private int currentSendPos;
    public boolean dataSendFinish;
    public int dataType;
    public long groupSize;
    public int groupType;
    public BleDataResponse mDataResponse;
    public int sendPriority;
    private int sendSN;
    public byte[] willData;

    public YCSendBean(byte[] bArr, int i2, BleDataResponse bleDataResponse) {
        this.willData = bArr;
        this.sendPriority = i2;
        this.mDataResponse = bleDataResponse;
        int i3 = SENDSN;
        SENDSN = i3 + 1;
        this.sendSN = i3;
        this.dataSendFinish = false;
        this.currentSendPos = 0;
    }

    public void collectStopReset() {
        this.currentSendPos = 0;
    }

    @Override // java.lang.Comparable
    public int compareTo(YCSendBean yCSendBean) {
        int i2 = this.sendPriority;
        int i3 = yCSendBean.sendPriority;
        return i2 == i3 ? this.sendSN - yCSendBean.sendSN : i3 - i2;
    }

    public int getCurrentSendPos() {
        return this.currentSendPos;
    }

    public void resetGroup(int i2, byte[] bArr) {
        this.currentSendPos = 0;
        this.dataType = i2;
        this.willData = bArr;
    }

    public String toString() {
        return String.format("%04X-%d-%04d-%04X", Integer.valueOf(this.dataType), Integer.valueOf(this.sendPriority), Integer.valueOf(this.sendSN), Integer.valueOf(this.groupType));
    }

    public byte[] willSendFrame() {
        byte[] bArr = this.willData;
        int length = bArr.length;
        int i2 = this.currentSendPos;
        int i3 = length - i2;
        if (i3 > 100000) {
            byte[] bArr2 = new byte[100000];
            System.arraycopy(bArr, i2, bArr2, 0, 100000);
            this.currentSendPos += 100000;
            return bArr2;
        }
        if (length > i2) {
            this.currentSendPos = i2 + i3;
            return bArr;
        }
        if (length != 0 || i2 != 0) {
            return null;
        }
        byte[] bArr3 = new byte[0];
        this.currentSendPos = 1;
        return bArr3;
    }
}
