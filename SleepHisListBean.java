package com.yucheng.smarthealthpro.home.activity.sleep.bean;

/* loaded from: classes3.dex */
public class SleepHisListBean {
    private int deepSleepCount;
    private int deepSleepTotal;
    private long endTime;
    private boolean isMonthWeekDay;
    private int lightSleepCount;
    private int lightSleepTotal;
    public int remTimes;
    private long startTime;
    private String state;
    private long totalTime;
    private int wakeCount;
    public int wakeDuration;

    public SleepHisListBean(long j2, long j3, long j4, int i2, int i3, int i4, int i5, int i6, String str, int i7, int i8, boolean z) {
        this.startTime = j2;
        this.endTime = j3;
        this.totalTime = j4;
        this.deepSleepTotal = i2;
        this.lightSleepTotal = i3;
        this.deepSleepCount = i4;
        this.lightSleepCount = i5;
        this.state = str;
        this.isMonthWeekDay = z;
        this.remTimes = i7;
        this.wakeCount = i6;
        this.wakeDuration = i8;
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

    public long getTotalTime() {
        return this.totalTime;
    }

    public void setTotalTime(long j2) {
        this.totalTime = j2;
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

    public int getWakeCount() {
        return this.wakeCount;
    }

    public void setWakeCount(int i2) {
        this.wakeCount = i2;
    }

    public String getState() {
        return this.state;
    }

    public void setState(String str) {
        this.state = str;
    }

    public boolean isMonthWeekDay() {
        return this.isMonthWeekDay;
    }

    public void setMonthWeekDay(boolean z) {
        this.isMonthWeekDay = z;
    }
}
