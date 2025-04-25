package com.yucheng.smarthealthpro.home.bean;

import com.dd.plist.ASCIIPropertyListParser;
import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/* loaded from: classes3.dex */
public class SleepResponse {
    private int code;
    private List<SleepDataBean> data;
    private int dataType;

    public static class SleepType {
        public static final int awake = 244;
        public static final int deepSleep = 241;
        public static final int lightSleep = 242;
        public static final int rem = 243;
        public static final int unknow = -1;
    }

    public int getCode() {
        return this.code;
    }

    public void setCode(int i2) {
        this.code = i2;
    }

    public List<SleepDataBean> getData() {
        return this.data;
    }

    public void setData(List<SleepDataBean> list) {
        this.data = list;
    }

    public int getDataType() {
        return this.dataType;
    }

    public void setDataType(int i2) {
        this.dataType = i2;
    }

    public static class SleepDataBean {
        private int deepSleepCount;
        private int deepSleepTotal;
        private long endTime;
        public boolean isUpload;
        private int lightSleepCount;
        private int lightSleepTotal;

        @SerializedName(alternate = {"remTimes"}, value = "rapidEyeMovementTotal")
        public int rapidEyeMovementTotal;
        private List<SleepData> sleepData;
        private long startTime;
        public int wakeCount;
        public int wakeDuration;

        public SleepDataBean(int i2, int i3, long j2, long j3, int i4, int i5, int i6, int i7, int i8, List<SleepData> list, boolean z) {
            new ArrayList();
            this.deepSleepCount = i2;
            this.lightSleepCount = i3;
            this.startTime = j2;
            this.endTime = j3;
            this.deepSleepTotal = i4;
            this.lightSleepTotal = i5;
            this.sleepData = list;
            this.isUpload = z;
            this.rapidEyeMovementTotal = i6;
            this.wakeCount = i7;
            this.wakeDuration = i8;
        }

        public int getDeepSleepCount() {
            return this.deepSleepCount;
        }

        public void setDeepSleepCount(int i2) {
            this.deepSleepCount = i2;
        }

        public int getLightSleepCount() {
            return this.lightSleepCount;
        }

        public void setLightSleepCount(int i2) {
            this.lightSleepCount = i2;
        }

        public long getStartTime() {
            return this.startTime;
        }

        public void setStartTime(long j2) {
            this.startTime = j2;
        }

        public long getEndTime() {
            return this.endTime;
        }

        public void setEndTime(long j2) {
            this.endTime = j2;
        }

        public int getDeepSleepTotal() {
            return this.deepSleepTotal;
        }

        public void setDeepSleepTotal(int i2) {
            this.deepSleepTotal = i2;
        }

        public int getLightSleepTotal() {
            return this.lightSleepTotal;
        }

        public void setLightSleepTotal(int i2) {
            this.lightSleepTotal = i2;
        }

        public List<SleepData> getSleepData() {
            return this.sleepData;
        }

        public void setSleepData(List<SleepData> list) {
            this.sleepData = list;
        }

        public boolean isUpload() {
            return this.isUpload;
        }

        public void setUpload(boolean z) {
            this.isUpload = z;
        }

        public String toString() {
            return "DataBean{deepSleepCount=" + this.deepSleepCount + ", lightSleepCount=" + this.lightSleepCount + ", startTime=" + this.startTime + ", endTime=" + this.endTime + ", deepSleepTotal=" + this.deepSleepTotal + ", lightSleepTotal=" + this.lightSleepTotal + ", sleepData=" + Arrays.toString(this.sleepData.toArray()) + ", isUpload=" + this.isUpload + ASCIIPropertyListParser.DICTIONARY_END_TOKEN;
        }

        public static class SleepData {

            @SerializedName(alternate = {"sleepLong"}, value = "sleepLen")
            private int sleepLen;

            @SerializedName(alternate = {"stime"}, value = "sleepStartTime")
            private long sleepStartTime;
            private int sleepType;

            public SleepData(long j2, int i2, int i3) {
                this.sleepStartTime = j2;
                this.sleepLen = i2;
                this.sleepType = i3;
            }

            public long getSleepStartTime() {
                return this.sleepStartTime;
            }

            public void setSleepStartTime(long j2) {
                this.sleepStartTime = j2;
            }

            public int getSleepLen() {
                return this.sleepLen;
            }

            public void setSleepLen(int i2) {
                this.sleepLen = i2;
            }

            public int getSleepType() {
                return this.sleepType;
            }

            public void setSleepType(int i2) {
                this.sleepType = i2;
            }
        }
    }
}
