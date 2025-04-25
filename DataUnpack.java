package com.yucheng.ycbtsdk.core;

import androidx.constraintlayout.core.motion.utils.TypedValues;
import com.facebook.internal.ServerProtocol;
import com.facebook.internal.security.CertificateUtil;
import com.google.firebase.crashlytics.buildtools.reloc.org.apache.commons.cli.HelpFormatter;
import com.google.gson.Gson;
import com.yucheng.ycbtsdk.AITools;
import com.yucheng.ycbtsdk.Constants;
import com.yucheng.ycbtsdk.YCBTClient;
import com.yucheng.ycbtsdk.bean.DialsBean;
import com.yucheng.ycbtsdk.bean.GsensorBean;
import com.yucheng.ycbtsdk.gatt.BleHelper;
import com.yucheng.ycbtsdk.jl.WatchManager;
import com.yucheng.ycbtsdk.utils.ByteUtil;
import com.yucheng.ycbtsdk.utils.SPUtil;
import com.yucheng.ycbtsdk.utils.YCBTLog;
import com.zhihu.matisse.internal.loader.AlbumLoader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.TimeZone;

/* loaded from: classes4.dex */
public class DataUnpack {
    private static ArrayList mBlockArray = new ArrayList();
    private static int totalCount = 0;
    private static int progress = 0;

    public static String byteToBinary(byte b2) {
        StringBuilder sb = new StringBuilder();
        for (int i2 = 7; i2 >= 0; i2--) {
            sb.append(((1 << i2) & b2) != 0 ? '1' : '0');
        }
        return sb.toString();
    }

    public static void removeAllFunction() {
        SPUtil.remove(Constants.FunctionConstant.ISHASSTEPCOUNT);
        SPUtil.remove(Constants.FunctionConstant.ISHASSLEEP);
        SPUtil.remove(Constants.FunctionConstant.ISHASREALDATA);
        SPUtil.remove(Constants.FunctionConstant.ISHASFIRMWAREUPDATE);
        SPUtil.remove(Constants.FunctionConstant.ISHASHEARTRATE);
        SPUtil.remove(Constants.FunctionConstant.ISHASINFORMATION);
        SPUtil.remove(Constants.FunctionConstant.ISHASMANYLANGUAGE);
        SPUtil.remove(Constants.FunctionConstant.ISHASBLOOD);
        SPUtil.remove(Constants.FunctionConstant.ISHASHEARTALARM);
        SPUtil.remove(Constants.FunctionConstant.ISHASBLOODALARM);
        SPUtil.remove(Constants.FunctionConstant.ISHASECGREALUPLOAD);
        SPUtil.remove(Constants.FunctionConstant.ISHASECGHISTORYUPLOAD);
        SPUtil.remove(Constants.FunctionConstant.ISHASBLOODOXYGEN);
        SPUtil.remove(Constants.FunctionConstant.ISHASRESPIRATORYRATE);
        SPUtil.remove(Constants.FunctionConstant.ISHASHRV);
        SPUtil.remove(Constants.FunctionConstant.ISHASMORESPORT);
        SPUtil.remove(Constants.FunctionConstant.ALARMCOUNT);
        SPUtil.remove(Constants.FunctionConstant.ISHASCUSTOM);
        SPUtil.remove(Constants.FunctionConstant.ISHASMEETING);
        SPUtil.remove(Constants.FunctionConstant.ISHASPARTY);
        SPUtil.remove(Constants.FunctionConstant.ISHASAPPOINT);
        SPUtil.remove(Constants.FunctionConstant.ISHASTAKEPILLS);
        SPUtil.remove(Constants.FunctionConstant.ISHASTAKEEXERCISE);
        SPUtil.remove(Constants.FunctionConstant.ISHASTAKESLEEP);
        SPUtil.remove(Constants.FunctionConstant.ISHASGETUP);
        SPUtil.remove(Constants.FunctionConstant.ISHASCALLPHONE);
        SPUtil.remove(Constants.FunctionConstant.ISHASMESSAGE);
        SPUtil.remove(Constants.FunctionConstant.ISHASEMAIL);
        SPUtil.remove(Constants.FunctionConstant.ISHASQQ);
        SPUtil.remove(Constants.FunctionConstant.ISHASWECHAT);
        SPUtil.remove(Constants.FunctionConstant.ISHASSINA);
        SPUtil.remove(Constants.FunctionConstant.ISHASFACEBOOK);
        SPUtil.remove(Constants.FunctionConstant.ISHASTWITTER);
        SPUtil.remove(Constants.FunctionConstant.ISHASWHATSAPP);
        SPUtil.remove(Constants.FunctionConstant.ISHASMESSENGER);
        SPUtil.remove(Constants.FunctionConstant.ISHASINSTAGRAM);
        SPUtil.remove(Constants.FunctionConstant.ISHASLINKEDIN);
        SPUtil.remove(Constants.FunctionConstant.ISHASLINE);
        SPUtil.remove(Constants.FunctionConstant.ISHASSNAPCHAT);
        SPUtil.remove(Constants.FunctionConstant.ISHASSKYPE);
        SPUtil.remove(Constants.FunctionConstant.ISHASOTHERMESSENGER);
        SPUtil.remove(Constants.FunctionConstant.ISHASLONGSITTING);
        SPUtil.remove(Constants.FunctionConstant.ISHASANTILOST);
        SPUtil.remove(Constants.FunctionConstant.ISHASFINDPHONE);
        SPUtil.remove(Constants.FunctionConstant.ISHASFINDDEVICE);
        SPUtil.remove(Constants.FunctionConstant.ISHASFACTORYSETTING);
        SPUtil.remove(Constants.FunctionConstant.ISHASBLOODLEVEL);
        SPUtil.remove(Constants.FunctionConstant.ISHASNOTITOGGLE);
        SPUtil.remove(Constants.FunctionConstant.ISHASLIFTBRIGHT);
        SPUtil.remove(Constants.FunctionConstant.ISHASSKINCOLOR);
        SPUtil.remove(Constants.FunctionConstant.ISHASWECHATSPORT);
        SPUtil.remove(Constants.FunctionConstant.ISHASSEARCHAROUND);
        SPUtil.remove(Constants.FunctionConstant.ISHASTODAYWEATHER);
        SPUtil.remove(Constants.FunctionConstant.ISHASTOMORROWWEATHER);
        SPUtil.remove(Constants.FunctionConstant.ISHASECGDIAGNOSIS);
        SPUtil.remove(Constants.FunctionConstant.ISHASPHONESUPPORT);
        SPUtil.remove(Constants.FunctionConstant.ISHASENCRYPTION);
        SPUtil.remove(Constants.FunctionConstant.ISHASTEMPALARM);
        SPUtil.remove(Constants.FunctionConstant.ISHASTEMPAXILLARYTEST);
        SPUtil.remove(Constants.FunctionConstant.ISHASCVRR);
        SPUtil.remove(Constants.FunctionConstant.ISHASBLOODPRESSURECALIBRATION);
        SPUtil.remove(Constants.FunctionConstant.ISHASECGRIGHTELECTRODE);
        SPUtil.remove(Constants.FunctionConstant.ISHASTHEME);
        SPUtil.remove(Constants.FunctionConstant.ISHASMUSIC);
        SPUtil.remove(Constants.FunctionConstant.ISHASTEMP);
        SPUtil.remove(Constants.FunctionConstant.ISHASINACCURATEECG);
        SPUtil.remove(Constants.FunctionConstant.ISHASCONTACTS);
        SPUtil.remove(Constants.FunctionConstant.ISHASDIAL);
        SPUtil.remove(Constants.FunctionConstant.ISHASFEMALEPHYSIOLOGICALCYCLE);
        SPUtil.remove(Constants.FunctionConstant.ISHASSHAKETAKEPHOTO);
        SPUtil.remove(Constants.FunctionConstant.ISHASMANUALTAKEPHOTO);
        SPUtil.remove(Constants.FunctionConstant.ISHASSETINFO);
        SPUtil.remove(Constants.FunctionConstant.ISHASTEMPCALIBRATION);
        SPUtil.remove(Constants.FunctionConstant.ISHASREALTIMEMONITORINGMODE);
        SPUtil.remove(Constants.FunctionConstant.ISHASINDOORWALKING);
        SPUtil.remove(Constants.FunctionConstant.ISHASOUTDOORWALKING);
        SPUtil.remove(Constants.FunctionConstant.ISHASINDOORRUNING);
        SPUtil.remove(Constants.FunctionConstant.ISHASOUTDOORRUNING);
        SPUtil.remove(Constants.FunctionConstant.ISHASPINGPONG);
        SPUtil.remove(Constants.FunctionConstant.ISHASFOOTBALL);
        SPUtil.remove(Constants.FunctionConstant.ISHASMOUNTAINCLIMBING);
        SPUtil.remove(Constants.FunctionConstant.ISHASRUNNING);
        SPUtil.remove(Constants.FunctionConstant.ISHASFITNESS);
        SPUtil.remove(Constants.FunctionConstant.ISHASRIDING);
        SPUtil.remove(Constants.FunctionConstant.ISHASROPESKIPPING);
        SPUtil.remove(Constants.FunctionConstant.ISHASBASKETBALL);
        SPUtil.remove(Constants.FunctionConstant.ISHASSWIMMING);
        SPUtil.remove(Constants.FunctionConstant.ISHASWALKING);
        SPUtil.remove(Constants.FunctionConstant.ISHASBADMINTON);
        SPUtil.remove(Constants.FunctionConstant.ISHASONFOOT);
        SPUtil.remove(Constants.FunctionConstant.ISHASYOGA);
        SPUtil.remove(Constants.FunctionConstant.ISHASWEIGHTTRAINING);
        SPUtil.remove(Constants.FunctionConstant.ISHASJUMPING);
        SPUtil.remove(Constants.FunctionConstant.ISHASSITUPS);
        SPUtil.remove(Constants.FunctionConstant.ISHASROWINGMACHINE);
        SPUtil.remove(Constants.FunctionConstant.ISHASSTEPPER);
        SPUtil.remove(Constants.FunctionConstant.ISHASINDOORRIDING);
        SPUtil.remove(Constants.FunctionConstant.ISHASREALEXERCISEDATA);
        SPUtil.remove(Constants.FunctionConstant.ISHATESTHEART);
        SPUtil.remove(Constants.FunctionConstant.ISHASTESTBLOOD);
        SPUtil.remove(Constants.FunctionConstant.ISHASTESTSPO2);
        SPUtil.remove(Constants.FunctionConstant.ISHASTESTTEMP);
        SPUtil.remove(Constants.FunctionConstant.ISHASTESTRESPIRATIONRATE);
        SPUtil.remove(Constants.FunctionConstant.ISHASKINDSINFORMATIONPUSH);
        SPUtil.remove(Constants.FunctionConstant.ISHASCUSTOMDIAL);
        SPUtil.remove(Constants.FunctionConstant.ISHASINFLATED);
        SPUtil.remove(Constants.FunctionConstant.ISHASSOS);
        SPUtil.remove(Constants.FunctionConstant.ISHASBLOODOXYGENALARM);
        SPUtil.remove(Constants.FunctionConstant.ISHASUPLOADINFLATEBLOOD);
        SPUtil.remove(Constants.FunctionConstant.ISHASVIBERNOTIFY);
        SPUtil.remove(Constants.FunctionConstant.ISHASOTHRENOTIFY);
        SPUtil.remove(Constants.FunctionConstant.ISFLIPDIALIMAGE);
        SPUtil.remove(Constants.FunctionConstant.WATCHSCREENBRIGHTNESS);
        SPUtil.remove(Constants.FunctionConstant.ISHASVIBRATIONINTENSITY);
        SPUtil.remove(Constants.FunctionConstant.ISHASSETSCREENTIME);
        SPUtil.remove(Constants.FunctionConstant.ISHASWATCHSCREENBRIGHTNESS);
        SPUtil.remove(Constants.FunctionConstant.ISHASBLOODSUGAR);
        SPUtil.remove(Constants.FunctionConstant.ISHASPAUSEEXERCISE);
        SPUtil.remove(Constants.FunctionConstant.ISHASDRINKWATERREMINDER);
        SPUtil.remove(Constants.FunctionConstant.ISHASBUSINESSCARD);
        SPUtil.remove(Constants.FunctionConstant.ISHASURICACIDMEASUREMENT);
        SPUtil.remove(Constants.FunctionConstant.ISHASVOLLEYBALL);
        SPUtil.remove(Constants.FunctionConstant.ISHASKAYAK);
        SPUtil.remove(Constants.FunctionConstant.ISHASROLLERSKATING);
        SPUtil.remove(Constants.FunctionConstant.ISHASTENNIS);
        SPUtil.remove(Constants.FunctionConstant.ISHASGOLF);
        SPUtil.remove(Constants.FunctionConstant.ISHASELLIPTICALMACHINE);
        SPUtil.remove(Constants.FunctionConstant.ISHASDANCE);
        SPUtil.remove(Constants.FunctionConstant.ISHASROCKCLIMBING);
        SPUtil.remove(Constants.FunctionConstant.ISHASAEROBICS);
        SPUtil.remove(Constants.FunctionConstant.ISHASOTHERSPORTS);
        SPUtil.remove(Constants.FunctionConstant.ISHASBLOODKETONEMEASUREMENT);
        SPUtil.remove(Constants.FunctionConstant.ISHASALIIOT);
        SPUtil.remove(Constants.FunctionConstant.ISHASCREATEBOND);
        SPUtil.remove(Constants.FunctionConstant.ISHASRESPIRATORYRATEALARM);
        SPUtil.remove(Constants.FunctionConstant.ISHASIMPRECISEBLOODFAT);
        SPUtil.remove(Constants.FunctionConstant.IS_HAS_RECORDING_FILE);
        SPUtil.remove(Constants.FunctionConstant.IS_HAS_PHYSIOTHERAPY);
        SPUtil.remove(Constants.FunctionConstant.IS_HAS_BATTERY_INFO_UPLOAD);
        SPUtil.remove(Constants.FunctionConstant.IS_HAS_PRESSURE_MEASUREMENT);
        SPUtil.remove(Constants.FunctionConstant.IS_HAS_OXYGENINTAKE_MEASUREMENT);
        SPUtil.remove(Constants.FunctionConstant.IS_HAS_PRECISION_BLOOD_GLUCOSE);
        SPUtil.remove(Constants.FunctionConstant.IS_HAS_PRECISION_BLOOD_KETONE);
        SPUtil.remove(Constants.FunctionConstant.IS_HAS_PRECISION_LIPIDS);
        SPUtil.remove(Constants.FunctionConstant.IS_HAS_PRECISION_URIC_ACID);
        SPUtil.remove(Constants.FunctionConstant.IS_HAS_Sporadic_Naps);
        SPUtil.remove(Constants.FunctionConstant.IS_HAS_MeasurementFunction);
    }

    public static void saveDeviceSupportFunctionData(byte[] bArr) {
        SPUtil.put(Constants.FunctionConstant.ISHASSTEPCOUNT, Integer.valueOf((bArr[0] >> 7) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASSLEEP, Integer.valueOf((bArr[0] >> 6) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASREALDATA, Integer.valueOf((bArr[0] >> 5) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASFIRMWAREUPDATE, Integer.valueOf((bArr[0] >> 4) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASHEARTRATE, Integer.valueOf((bArr[0] >> 3) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASINFORMATION, Integer.valueOf((bArr[0] >> 2) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASMANYLANGUAGE, Integer.valueOf((bArr[0] >> 1) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASBLOOD, Integer.valueOf(bArr[0] & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASHEARTALARM, Integer.valueOf((bArr[1] >> 7) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASBLOODALARM, Integer.valueOf((bArr[1] >> 6) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASECGREALUPLOAD, Integer.valueOf((bArr[1] >> 5) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASECGHISTORYUPLOAD, Integer.valueOf((bArr[1] >> 4) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASBLOODOXYGEN, Integer.valueOf((bArr[1] >> 3) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASRESPIRATORYRATE, Integer.valueOf((bArr[1] >> 2) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASHRV, Integer.valueOf((bArr[1] >> 1) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASMORESPORT, Integer.valueOf(bArr[1] & 1));
        SPUtil.put(Constants.FunctionConstant.ALARMCOUNT, Integer.valueOf(bArr[2] & 255));
        SPUtil.put(Constants.FunctionConstant.ISHASCUSTOM, Integer.valueOf((bArr[3] >> 7) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASMEETING, Integer.valueOf((bArr[3] >> 6) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASPARTY, Integer.valueOf((bArr[3] >> 5) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASAPPOINT, Integer.valueOf((bArr[3] >> 4) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASTAKEPILLS, Integer.valueOf((bArr[3] >> 3) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASTAKEEXERCISE, Integer.valueOf((bArr[3] >> 2) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASTAKESLEEP, Integer.valueOf((bArr[3] >> 1) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASGETUP, Integer.valueOf(bArr[3] & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASCALLPHONE, Integer.valueOf((bArr[4] >> 7) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASMESSAGE, Integer.valueOf((bArr[4] >> 6) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASEMAIL, Integer.valueOf((bArr[4] >> 5) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASQQ, Integer.valueOf((bArr[4] >> 4) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASWECHAT, Integer.valueOf((bArr[4] >> 3) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASSINA, Integer.valueOf((bArr[4] >> 2) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASFACEBOOK, Integer.valueOf((bArr[4] >> 1) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASTWITTER, Integer.valueOf(bArr[4] & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASWHATSAPP, Integer.valueOf((bArr[5] >> 7) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASMESSENGER, Integer.valueOf((bArr[5] >> 6) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASINSTAGRAM, Integer.valueOf((bArr[5] >> 5) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASLINKEDIN, Integer.valueOf((bArr[5] >> 4) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASLINE, Integer.valueOf((bArr[5] >> 3) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASSNAPCHAT, Integer.valueOf((bArr[5] >> 2) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASSKYPE, Integer.valueOf((bArr[5] >> 1) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASOTHERMESSENGER, Integer.valueOf(bArr[5] & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASLONGSITTING, Integer.valueOf((bArr[6] >> 7) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASANTILOST, Integer.valueOf((bArr[6] >> 6) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASFINDPHONE, Integer.valueOf((bArr[6] >> 5) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASFINDDEVICE, Integer.valueOf((bArr[6] >> 4) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASFACTORYSETTING, Integer.valueOf((bArr[6] >> 3) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASBLOODLEVEL, Integer.valueOf((bArr[6] >> 2) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASNOTITOGGLE, Integer.valueOf((bArr[6] >> 1) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASLIFTBRIGHT, Integer.valueOf(bArr[6] & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASSKINCOLOR, Integer.valueOf((bArr[7] >> 7) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASWECHATSPORT, Integer.valueOf((bArr[7] >> 6) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASSEARCHAROUND, Integer.valueOf((bArr[7] >> 5) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASTODAYWEATHER, Integer.valueOf((bArr[7] >> 4) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASTOMORROWWEATHER, Integer.valueOf((bArr[7] >> 3) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASECGDIAGNOSIS, Integer.valueOf((bArr[7] >> 2) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASPHONESUPPORT, Integer.valueOf((bArr[7] >> 1) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASENCRYPTION, Integer.valueOf(bArr[7] & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASTEMPALARM, Integer.valueOf((bArr[8] >> 7) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASTEMPAXILLARYTEST, Integer.valueOf((bArr[8] >> 6) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASCVRR, Integer.valueOf((bArr[8] >> 5) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASBLOODPRESSURECALIBRATION, Integer.valueOf((bArr[8] >> 4) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASECGRIGHTELECTRODE, Integer.valueOf((bArr[8] >> 3) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASTHEME, Integer.valueOf((bArr[8] >> 2) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASMUSIC, Integer.valueOf((bArr[8] >> 1) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASTEMP, Integer.valueOf(bArr[8] & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASINACCURATEECG, Integer.valueOf((bArr[9] >> 7) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASCONTACTS, Integer.valueOf((bArr[9] >> 6) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASDIAL, Integer.valueOf((bArr[9] >> 5) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASFEMALEPHYSIOLOGICALCYCLE, Integer.valueOf((bArr[9] >> 4) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASSHAKETAKEPHOTO, Integer.valueOf((bArr[9] >> 3) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASMANUALTAKEPHOTO, Integer.valueOf((bArr[9] >> 2) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASSETINFO, Integer.valueOf((bArr[9] >> 1) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASTEMPCALIBRATION, Integer.valueOf(bArr[9] & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASREALTIMEMONITORINGMODE, Integer.valueOf((bArr[10] >> 7) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASINDOORWALKING, Integer.valueOf((bArr[10] >> 6) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASOUTDOORWALKING, Integer.valueOf((bArr[10] >> 5) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASINDOORRUNING, Integer.valueOf((bArr[10] >> 4) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASOUTDOORRUNING, Integer.valueOf((bArr[10] >> 3) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASPINGPONG, Integer.valueOf((bArr[10] >> 2) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASFOOTBALL, Integer.valueOf((bArr[10] >> 1) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASMOUNTAINCLIMBING, Integer.valueOf(bArr[10] & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASRUNNING, Integer.valueOf((bArr[11] >> 7) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASFITNESS, Integer.valueOf((bArr[11] >> 6) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASRIDING, Integer.valueOf((bArr[11] >> 5) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASROPESKIPPING, Integer.valueOf((bArr[11] >> 4) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASBASKETBALL, Integer.valueOf((bArr[11] >> 3) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASSWIMMING, Integer.valueOf((bArr[11] >> 2) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASWALKING, Integer.valueOf((bArr[11] >> 1) & 1));
        SPUtil.put(Constants.FunctionConstant.ISHASBADMINTON, Integer.valueOf(bArr[11] & 1));
        if (bArr.length >= 18) {
            if (bArr.length >= 20) {
                SPUtil.put(Constants.FunctionConstant.ISHASONFOOT, Integer.valueOf((bArr[14] >> 7) & 1));
            }
            SPUtil.put(Constants.FunctionConstant.ISHASYOGA, Integer.valueOf((bArr[14] >> 6) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASWEIGHTTRAINING, Integer.valueOf((bArr[14] >> 5) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASJUMPING, Integer.valueOf((bArr[14] >> 4) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASSITUPS, Integer.valueOf((bArr[14] >> 3) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASROWINGMACHINE, Integer.valueOf((bArr[14] >> 2) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASSTEPPER, Integer.valueOf((bArr[14] >> 1) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASINDOORRIDING, Integer.valueOf(bArr[14] & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASREALEXERCISEDATA, Integer.valueOf(bArr[15] & 1));
            SPUtil.put(Constants.FunctionConstant.ISHATESTHEART, Integer.valueOf((bArr[15] >> 1) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASTESTBLOOD, Integer.valueOf((bArr[15] >> 2) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASTESTSPO2, Integer.valueOf((bArr[15] >> 3) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASTESTTEMP, Integer.valueOf((bArr[15] >> 4) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASTESTRESPIRATIONRATE, Integer.valueOf((bArr[15] >> 5) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASKINDSINFORMATIONPUSH, Integer.valueOf((bArr[15] >> 6) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASCUSTOMDIAL, Integer.valueOf((bArr[15] >> 7) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASINFLATED, Integer.valueOf(bArr[16] & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASSOS, Integer.valueOf((bArr[16] >> 1) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASBLOODOXYGENALARM, Integer.valueOf((bArr[16] >> 2) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASUPLOADINFLATEBLOOD, Integer.valueOf((bArr[16] >> 3) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASVIBERNOTIFY, Integer.valueOf((bArr[16] >> 4) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASOTHRENOTIFY, Integer.valueOf((bArr[16] >> 5) & 1));
            SPUtil.put(Constants.FunctionConstant.ISFLIPDIALIMAGE, Integer.valueOf((bArr[16] >> 6) & 1));
            SPUtil.put(Constants.FunctionConstant.WATCHSCREENBRIGHTNESS, Integer.valueOf((bArr[16] >> 7) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASVIBRATIONINTENSITY, Integer.valueOf(bArr[17] & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASSETSCREENTIME, Integer.valueOf((bArr[17] >> 1) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASWATCHSCREENBRIGHTNESS, Integer.valueOf(((bArr[17] >> 2) & 1) ^ 1));
            SPUtil.put(Constants.FunctionConstant.ISHASBLOODSUGAR, Integer.valueOf((bArr[17] >> 3) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASPAUSEEXERCISE, Integer.valueOf((bArr[17] >> 4) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASDRINKWATERREMINDER, Integer.valueOf((bArr[17] >> 5) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASBUSINESSCARD, Integer.valueOf((bArr[17] >> 6) & 1));
            SPUtil.put(Constants.FunctionConstant.ISHASURICACIDMEASUREMENT, Integer.valueOf((bArr[17] >> 7) & 1));
            if (bArr.length >= 20) {
                SPUtil.put(Constants.FunctionConstant.ISHASVOLLEYBALL, Integer.valueOf(bArr[18] & 1));
                SPUtil.put(Constants.FunctionConstant.ISHASKAYAK, Integer.valueOf((bArr[18] >> 1) & 1));
                SPUtil.put(Constants.FunctionConstant.ISHASROLLERSKATING, Integer.valueOf((bArr[18] >> 2) & 1));
                SPUtil.put(Constants.FunctionConstant.ISHASTENNIS, Integer.valueOf((bArr[18] >> 3) & 1));
                SPUtil.put(Constants.FunctionConstant.ISHASGOLF, Integer.valueOf((bArr[18] >> 4) & 1));
                SPUtil.put(Constants.FunctionConstant.ISHASELLIPTICALMACHINE, Integer.valueOf((bArr[18] >> 5) & 1));
                SPUtil.put(Constants.FunctionConstant.ISHASDANCE, Integer.valueOf((bArr[18] >> 6) & 1));
                SPUtil.put(Constants.FunctionConstant.ISHASROCKCLIMBING, Integer.valueOf((bArr[18] >> 7) & 1));
                SPUtil.put(Constants.FunctionConstant.ISHASAEROBICS, Integer.valueOf(bArr[19] & 1));
                SPUtil.put(Constants.FunctionConstant.ISHASOTHERSPORTS, Integer.valueOf((bArr[19] >> 1) & 1));
                if (bArr.length >= 21) {
                    SPUtil.put(Constants.FunctionConstant.ISHASBLOODKETONEMEASUREMENT, Integer.valueOf(bArr[20] & 1));
                    SPUtil.put(Constants.FunctionConstant.ISHASALIIOT, Integer.valueOf((bArr[20] >> 1) & 1));
                    SPUtil.put(Constants.FunctionConstant.ISHASCREATEBOND, Integer.valueOf((bArr[20] >> 2) & 1));
                    SPUtil.put(Constants.FunctionConstant.ISHASRESPIRATORYRATEALARM, Integer.valueOf((bArr[20] >> 3) & 1));
                    SPUtil.put(Constants.FunctionConstant.ISHASIMPRECISEBLOODFAT, Integer.valueOf((bArr[20] >> 4) & 1));
                    SPUtil.put(Constants.FunctionConstant.IS_HAS_INDEPENDENT_AUTOMATIC_TIME_MEASUREMENT, Integer.valueOf((bArr[20] >> 5) & 1));
                    SPUtil.put(Constants.FunctionConstant.IS_HAS_RECORDING_FILE, Integer.valueOf((bArr[20] >> 6) & 1));
                    SPUtil.put(Constants.FunctionConstant.IS_HAS_PHYSIOTHERAPY, Integer.valueOf((bArr[20] >> 7) & 1));
                    if (bArr.length >= 22) {
                        SPUtil.put(Constants.FunctionConstant.ISHASZOOMNOTIFY, Integer.valueOf(bArr[21] & 1));
                        SPUtil.put(Constants.FunctionConstant.ISHASTIKTOKNOTIFY, Integer.valueOf((bArr[21] >> 1) & 1));
                        SPUtil.put(Constants.FunctionConstant.ISHASKAKAOTALKNOTIFY, Integer.valueOf((bArr[21] >> 2) & 1));
                    }
                    if (bArr.length >= 23) {
                        SPUtil.put(Constants.FunctionConstant.IS_HAS_SLEEP_REMIND, Integer.valueOf(bArr[22] & 1));
                        SPUtil.put(Constants.FunctionConstant.IS_HAS_DEVICE_SPEC, Integer.valueOf((bArr[22] >> 1) & 1));
                        SPUtil.put(Constants.FunctionConstant.IS_HAS_LOCAL_SPORT_DATA, Integer.valueOf((bArr[22] >> 2) & 1));
                        SPUtil.put(Constants.FunctionConstant.IS_HAS_LOGO, Integer.valueOf((bArr[22] >> 3) & 1));
                        SPUtil.put(Constants.FunctionConstant.IS_MOTION_DELAY_DISCONNECT, Integer.valueOf((bArr[22] >> 4) & 1));
                        SPUtil.put(Constants.FunctionConstant.IS_HAS_BATTERY_INFO_UPLOAD, Integer.valueOf((bArr[22] >> 5) & 1));
                        SPUtil.put(Constants.FunctionConstant.IS_HAS_PRESSURE, Integer.valueOf((bArr[22] >> 6) & 1));
                        SPUtil.put(Constants.FunctionConstant.IS_HAS_MAXIMAL_OXYGEN_INTAKE, Integer.valueOf((bArr[22] >> 7) & 1));
                    }
                    if (bArr.length >= 24) {
                        SPUtil.put(Constants.FunctionConstant.IS_HAS_HRV_MEASUREMENT, Integer.valueOf(bArr[23] & 1));
                        SPUtil.put("isHasBloodSugarMeasurement", Integer.valueOf((bArr[23] >> 1) & 1));
                        SPUtil.put(Constants.FunctionConstant.IS_HAS_PRESSURE_MEASUREMENT, Integer.valueOf((bArr[23] >> 2) & 1));
                        SPUtil.put(Constants.FunctionConstant.IS_HAS_OXYGENINTAKE_MEASUREMENT, Integer.valueOf((bArr[23] >> 3) & 1));
                    }
                    if (bArr.length >= 25) {
                        SPUtil.put(Constants.FunctionConstant.IS_HAS_PRECISION_BLOOD_GLUCOSE, Integer.valueOf(bArr[24] & 1));
                        SPUtil.put(Constants.FunctionConstant.IS_HAS_PRECISION_LIPIDS, Integer.valueOf((bArr[24] >> 1) & 1));
                        SPUtil.put(Constants.FunctionConstant.IS_HAS_PRECISION_URIC_ACID, Integer.valueOf((bArr[24] >> 2) & 1));
                        SPUtil.put(Constants.FunctionConstant.IS_HAS_PRECISION_BLOOD_KETONE, Integer.valueOf((bArr[24] >> 3) & 1));
                    }
                    if (bArr.length >= 26) {
                        SPUtil.put(Constants.FunctionConstant.IS_HAS_Sporadic_Naps, Integer.valueOf(bArr[25] & 1));
                        SPUtil.put(Constants.FunctionConstant.IS_HAS_MeasurementFunction, Integer.valueOf((bArr[25] >> 1) & 1));
                    }
                }
            }
        }
    }

    public static HashMap unpackAlarmData(byte[] bArr) {
        HashMap hashMap = new HashMap();
        int i2 = 0;
        hashMap.put("code", 0);
        byte b2 = bArr[0];
        int i3 = 3;
        if (b2 < 1 || b2 > 3) {
            byte b3 = bArr[1];
            byte b4 = bArr[2];
            YCBTLog.e("支持闹钟数量" + ((int) b3) + "已设置闹钟数据:" + ((int) b4));
            ArrayList arrayList = new ArrayList();
            if (b4 > 0) {
                while (i2 < b4) {
                    int i4 = i3 + 1;
                    int i5 = bArr[i3] & 255;
                    int i6 = i4 + 1;
                    int i7 = bArr[i4] & 255;
                    int i8 = i6 + 1;
                    int i9 = bArr[i6] & 255;
                    int i10 = i8 + 1;
                    int i11 = bArr[i8] & 255;
                    int i12 = i10 + 1;
                    int i13 = bArr[i10] & 255;
                    HashMap hashMap2 = new HashMap();
                    hashMap2.put("alarmType", Integer.valueOf(i5));
                    hashMap2.put("alarmHour", Integer.valueOf(i7));
                    hashMap2.put("alarmMin", Integer.valueOf(i9));
                    hashMap2.put("alarmRepeat", Integer.valueOf(i11));
                    hashMap2.put("alarmDelayTime", Integer.valueOf(i13));
                    arrayList.add(hashMap2);
                    i2++;
                    i3 = i12;
                }
            }
            hashMap.put("data", arrayList);
            hashMap.put("tSupportAlarmNum", Integer.valueOf(b3));
            hashMap.put("tSettedAlarmNum", Integer.valueOf(b4));
            hashMap.put("optType", Integer.valueOf(b2));
        } else {
            byte b5 = bArr[1];
            hashMap.put("optType", Integer.valueOf(b2));
            hashMap.put("code", Integer.valueOf(b5));
        }
        hashMap.put("dataType", 257);
        return hashMap;
    }

    public static HashMap unpackAppEcgPpgStatus(byte[] bArr) {
        int i2 = bArr[0] & 255;
        int i3 = bArr[1] & 255;
        YCBTLog.e("心电电极状态: " + i2 + "光电传感器状态: " + i3);
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.AppECGPPGStatus));
        hashMap.put("EcgStatus", Integer.valueOf(i2));
        hashMap.put("PPGStatus", Integer.valueOf(i3));
        return hashMap;
    }

    public static HashMap unpackBodyData(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null) {
            int i2 = bArr[0] & 255;
            int i3 = bArr[1] & 255;
            int i4 = bArr[2] & 255;
            int i5 = bArr[3] & 255;
            int i6 = bArr[4] & 255;
            int i7 = bArr[5] & 255;
            int i8 = bArr[6] & 255;
            int i9 = bArr[7] & 255;
            int i10 = bArr[8] & 255;
            int i11 = bArr[9] & 255;
            int i12 = (bArr[10] & 255) + ((bArr[11] & 255) << 8);
            hashMap.put("loadIndexInteger", Integer.valueOf(i2));
            hashMap.put("loadIndexFloat", Integer.valueOf(i3));
            hashMap.put("hrvInteger", Integer.valueOf(i4));
            hashMap.put("hrvFloat", Integer.valueOf(i5));
            hashMap.put("pressureInteger", Integer.valueOf(i6));
            hashMap.put("pressureFloat", Integer.valueOf(i7));
            hashMap.put("bodyInteger", Integer.valueOf(i8));
            hashMap.put("bodyFloat", Integer.valueOf(i9));
            hashMap.put("sympatheticInteger", Integer.valueOf(i10));
            hashMap.put("sympatheticFloat", Integer.valueOf(i11));
            hashMap.put("sdn", Integer.valueOf(i12));
        }
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Real_UploadBodyData));
        return hashMap;
    }

    public static HashMap unpackCollectSummaryInfo(byte[] bArr) {
        int offset = TimeZone.getDefault().getOffset(System.currentTimeMillis());
        int i2 = bArr[0] & 255;
        int i3 = (bArr[1] & 255) + ((bArr[2] & 255) << 8);
        long j2 = (bArr[3] & 255) + ((bArr[4] & 255) << 8) + ((bArr[5] & 255) << 16) + ((bArr[6] & 255) << 24);
        long j3 = (946684800 + j2) * 1000;
        int i4 = (bArr[7] & 255) + ((bArr[8] & 255) << 8);
        int i5 = bArr[9] & 255;
        long j4 = (bArr[10] & 255) + ((bArr[11] & 255) << 8) + ((bArr[12] & 255) << 16) + ((bArr[13] & 255) << 24);
        int i6 = (bArr[14] & 255) + ((bArr[15] & 255) << 8);
        YCBTLog.e("SN=" + i3 + " tStartTime=" + j2 + " realTime=" + j3 + " tDataTotalLen=" + j4 + " collectBlockNum=" + i6 + " collectDigits=" + i5 + " samplingRate=" + i4);
        HashMap hashMap = new HashMap();
        hashMap.put("collectType", Integer.valueOf(i2));
        hashMap.put("collectSN", Integer.valueOf(i3));
        hashMap.put("collectSendTime", Long.valueOf(j2));
        hashMap.put("collectStartTime", Long.valueOf(j3 - offset));
        hashMap.put("collectTotalLen", Long.valueOf(j4));
        hashMap.put("collectBlockNum", Integer.valueOf(i6));
        hashMap.put("collectDigits", Integer.valueOf(i5));
        hashMap.put("samplingRate", Integer.valueOf(i4));
        return hashMap;
    }

    public static HashMap unpackContacts(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null && bArr.length > 1) {
            hashMap.put("data", Integer.valueOf(bArr[1] & 255));
        }
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.AppPushContacts));
        return hashMap;
    }

    public static HashMap<String, Object> unpackCustomizeCGM(byte[] bArr) {
        HashMap<String, Object> hashMap = new HashMap<>();
        hashMap.put("code", 0);
        try {
            if ((bArr[0] & 255) == 1) {
                byte[] bArr2 = new byte[16];
                System.arraycopy(bArr, 5, bArr2, 0, 16);
                hashMap.put("startTime", Long.valueOf(((((((bArr[1] & 255) + ((bArr[2] & 255) << 8)) + ((bArr[3] & 255) << 16)) + ((bArr[4] & 255) << 24)) + 946684800) * 1000) - TimeZone.getDefault().getOffset(System.currentTimeMillis())));
                hashMap.put("serial", ByteUtil.byteToStr(bArr2));
            }
        } catch (Exception e2) {
            hashMap.put("code", 1);
            e2.printStackTrace();
        }
        return hashMap;
    }

    public static HashMap<String, Object> unpackCustomizeData(byte[] bArr) {
        HashMap<String, Object> hashMap = new HashMap<>();
        char c2 = 0;
        int i2 = bArr[0] & 255;
        int i3 = bArr[1] & 255;
        hashMap.put("dataType", 3445);
        hashMap.put("code", 0);
        hashMap.put("opcode", Integer.valueOf(i2));
        hashMap.put("type", Integer.valueOf(i3));
        int i4 = 8;
        if (i2 == 1) {
            int i5 = bArr[2] & 255;
            int i6 = (bArr[3] & 255) + ((bArr[4] & 255) << 8) + ((bArr[5] & 255) << 16) + ((bArr[6] & 255) << 24);
            int i7 = (bArr[7] & 255) + ((bArr[8] & 255) << 8);
            int i8 = (bArr[9] & 255) + ((bArr[10] & 255) << 8) + ((bArr[11] & 255) << 16) + ((bArr[12] & 255) << 24);
            YCBTLog.e(i5 + CertificateUtil.DELIMITER + i6 + CertificateUtil.DELIMITER + i7 + CertificateUtil.DELIMITER + i8);
            hashMap.put(ServerProtocol.DIALOG_PARAM_STATE, Integer.valueOf(i5));
            hashMap.put(AlbumLoader.COLUMN_COUNT, Integer.valueOf(i6));
            hashMap.put("packageNum", Integer.valueOf(i7));
            hashMap.put("total", Integer.valueOf(i8));
            totalCount = i7;
            progress = 0;
            mBlockArray.clear();
            mBlockArray.add(117);
        } else if (i2 == 2) {
            progress++;
            mBlockArray.add(bArr);
            hashMap.put("progress", String.format("%.1f", Float.valueOf((progress * 1.0f) / (totalCount * 100.0f))));
        } else if (i2 == 3) {
            hashMap.put(ServerProtocol.DIALOG_PARAM_STATE, Integer.valueOf(bArr[2] & 255));
        } else if (i2 == 128) {
            byte b2 = bArr[2];
            byte b3 = bArr[3];
            int i9 = (bArr[4] & 255) + ((bArr[5] & 255) << 8) + ((bArr[6] & 255) << 16) + ((bArr[7] & 255) << 24);
            int i10 = (bArr[8] & 255) + ((bArr[9] & 255) << 8);
            byte[] bArr2 = new byte[i9];
            ((Integer) mBlockArray.get(0)).intValue();
            int i11 = 0;
            int i12 = 1;
            while (i12 < mBlockArray.size()) {
                byte[] bArr3 = (byte[]) mBlockArray.get(i12);
                byte b4 = bArr3[c2];
                byte b5 = bArr3[1];
                int i13 = (bArr3[2] & 255) + ((bArr3[3] & 255) << 8);
                System.arraycopy(bArr3, 4, bArr2, i11, i13);
                i11 += i13;
                i12++;
                c2 = 0;
            }
            if (ByteUtil.crc16_compute(bArr2, i11) == i10) {
                ArrayList arrayList = new ArrayList();
                if (i3 == 1) {
                    int i14 = 0;
                    while (i14 + 6 <= i9) {
                        HashMap hashMap2 = new HashMap();
                        int i15 = i14 + 1;
                        int i16 = i15 + 1;
                        int i17 = (bArr2[i14] & 255) + ((bArr2[i15] & 255) << 8);
                        int i18 = i16 + 1;
                        int i19 = i18 + 1;
                        int i20 = (bArr2[i16] & 255) + ((bArr2[i18] & 255) << 8);
                        int i21 = i19 + 1;
                        i14 = i21 + 1;
                        int i22 = (bArr2[i19] & 255) + ((bArr2[i21] & 255) << 8);
                        hashMap2.put(TypedValues.CycleType.S_WAVE_OFFSET, Integer.valueOf(i17));
                        hashMap2.put("cgm", Float.valueOf((i20 * 1.0f) / 100.0f));
                        hashMap2.put("ele", Float.valueOf((i22 * 1.0f) / 100.0f));
                        arrayList.add(hashMap2);
                    }
                } else if (i3 == 2) {
                    int offset = TimeZone.getDefault().getOffset(System.currentTimeMillis());
                    int i23 = 0;
                    while (i23 + 12 <= i9) {
                        HashMap hashMap3 = new HashMap();
                        int i24 = i23 + 1;
                        int i25 = i24 + 1;
                        int i26 = (bArr2[i23] & 255) + ((bArr2[i24] & 255) << i4);
                        int i27 = i25 + 1;
                        int i28 = i26 + ((bArr2[i25] & 255) << 16);
                        int i29 = i27 + 1;
                        long j2 = i28 + ((bArr2[i27] & 255) << 24);
                        YCBTLog.e("physiotherapyStartTime=" + j2 + " 946684800");
                        long j3 = (j2 + 946684800) * 1000;
                        int i30 = i29 + 1;
                        int i31 = i30 + 1;
                        int i32 = (bArr2[i29] & 255) + ((bArr2[i30] & 255) << i4);
                        int i33 = i31 + 1;
                        int i34 = i32 + ((bArr2[i31] & 255) << 16);
                        int i35 = i33 + 1;
                        int i36 = i34 + ((bArr2[i33] & 255) << 24);
                        int i37 = i35 + 1;
                        int i38 = bArr2[i35] & 255;
                        int i39 = i37 + 1;
                        int i40 = bArr2[i37] & 255;
                        int i41 = i39 + 1;
                        int i42 = bArr2[i39] & 255;
                        i23 = i41 + 1;
                        int i43 = bArr2[i41] & 255;
                        YCBTLog.e("physiotherapyStartTime=" + j3 + " " + offset);
                        hashMap3.put("physiotherapyStartTime", Long.valueOf(j3 - offset));
                        hashMap3.put("physiotherapyDuration", Integer.valueOf(i36));
                        hashMap3.put("physiotherapyType", Integer.valueOf(i38));
                        hashMap3.put("physiotherapyStartType", Integer.valueOf(i40));
                        hashMap3.put("physiotherapyPowerLevel", Integer.valueOf(i42));
                        hashMap3.put("physiotherapyDurationLevel", Integer.valueOf(i43));
                        arrayList.add(hashMap3);
                        i4 = 8;
                    }
                }
                hashMap.put("data", arrayList);
            } else {
                hashMap.put("code", 1);
            }
            mBlockArray.clear();
        }
        return hashMap;
    }

    public static HashMap unpackDeviceInfoData(byte[] bArr) {
        StringBuilder sb;
        StringBuilder append;
        HashMap hashMap;
        HashMap hashMap2 = new HashMap();
        int i2 = 0;
        hashMap2.put("code", 0);
        int i3 = (bArr[0] & 255) + ((bArr[1] & 255) << 8);
        int i4 = bArr[2] & 255;
        int i5 = bArr[3] & 255;
        int i6 = bArr[4] & 255;
        int i7 = bArr[5] & 255;
        int i8 = bArr[6] & 255;
        int i9 = bArr[7] & 255;
        YCBTLog.e("设备ID " + i3 + " 版本号 " + i5 + "." + i4 + " 电量 " + i7 + "--state==" + i6);
        if (i4 < 10) {
            sb = new StringBuilder();
            append = sb.append(i5).append(".0");
        } else {
            sb = new StringBuilder();
            append = sb.append(i5).append(".");
        }
        String sb2 = append.append(i4).toString();
        SPUtil.saveBindedDeviceVersion(sb2);
        SPUtil.saveDeviceBatteryState(i6);
        SPUtil.saveDeviceBatteryValue(i7);
        HashMap hashMap3 = new HashMap();
        hashMap3.put("deviceId", Integer.valueOf(i3));
        hashMap3.put("deviceVersion", sb2);
        hashMap3.put("deviceBatteryState", Integer.valueOf(i6));
        hashMap3.put("deviceBatteryValue", Integer.valueOf(i7));
        hashMap3.put("deviceMainVersion", Integer.valueOf(i5));
        hashMap3.put("deviceSubVersion", Integer.valueOf(i4));
        hashMap3.put("devicetBindState", Integer.valueOf(i8));
        hashMap3.put("devicetSyncState", Integer.valueOf(i9));
        if (bArr.length >= 24) {
            int i10 = bArr[8] & 255;
            int i11 = bArr[9] & 255;
            int i12 = bArr[10] & 255;
            int i13 = bArr[11] & 255;
            int i14 = bArr[12] & 255;
            int i15 = bArr[13] & 255;
            int i16 = bArr[14] & 255;
            int i17 = bArr[15] & 255;
            int i18 = bArr[16] & 255;
            int i19 = bArr[17] & 255;
            int i20 = bArr[18] & 255;
            hashMap = hashMap2;
            hashMap3.put("bleAgreementSubVersion", Integer.valueOf(i10));
            hashMap3.put("bleAgreementMainVersion", Integer.valueOf(i11));
            hashMap3.put("bloodAlgoSubVersion", Integer.valueOf(i12));
            hashMap3.put("bloodAlgoMainVersion", Integer.valueOf(i13));
            hashMap3.put("tpSubVersion", Integer.valueOf(i14));
            hashMap3.put("tpMainVersion", Integer.valueOf(i15));
            hashMap3.put("bloodSugarSubVersion", Integer.valueOf(i16));
            hashMap3.put("bloodSugarMainVersion", Integer.valueOf(i17));
            hashMap3.put("uiSubVersion", Integer.valueOf(i18));
            hashMap3.put("uiMainVersion", Integer.valueOf(i19));
            hashMap3.put("hardwareType", Integer.valueOf(i20));
            if (i17 == 0 && i16 == 0) {
                SPUtil.saveBloodSugarVersion("");
            } else {
                SPUtil.saveBloodSugarVersion(i17 + "." + i16);
            }
            i2 = i20;
        } else {
            hashMap = hashMap2;
            SPUtil.saveBloodSugarVersion("");
        }
        SPUtil.saveHardwareType(i2);
        hashMap3.put("hardwareType", Integer.valueOf(i2));
        HashMap hashMap4 = hashMap;
        hashMap4.put("dataType", 512);
        hashMap4.put("data", hashMap3);
        return hashMap4;
    }

    public static HashMap unpackDeviceName(byte[] bArr) {
        int length = bArr.length - 1;
        byte[] bArr2 = new byte[length];
        System.arraycopy(bArr, 0, bArr2, 0, length);
        String str = new String(bArr2);
        YCBTLog.e("DeviceName:".concat(str));
        SPUtil.put(Constants.FunctionConstant.DEVICETYPE, str);
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", 515);
        hashMap.put("data", str);
        return hashMap;
    }

    public static HashMap unpackDeviceScreenInfo(byte[] bArr) {
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        if (bArr.length >= 8) {
            int i2 = (bArr[0] & 255) + ((bArr[1] & 255) << 8);
            int i3 = (bArr[2] & 255) + ((bArr[3] & 255) << 8);
            int i4 = (bArr[4] & 255) + ((bArr[5] & 255) << 8);
            int i5 = (bArr[6] & 255) + ((bArr[7] & 255) << 8);
            int i6 = (int) ((i3 / i5) * (i2 / i4) * 0.8d);
            hashMap.put(AlbumLoader.COLUMN_COUNT, Integer.valueOf(i6));
            System.out.println("chong------with==" + i2 + HelpFormatter.DEFAULT_LONG_OPT_PREFIX + i3 + HelpFormatter.DEFAULT_LONG_OPT_PREFIX + i4 + HelpFormatter.DEFAULT_LONG_OPT_PREFIX + i5 + HelpFormatter.DEFAULT_LONG_OPT_PREFIX + i6);
        }
        hashMap.put("dataType", 523);
        return hashMap;
    }

    public static HashMap unpackDeviceUserConfigData(byte[] bArr) {
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", 519);
        if (bArr.length >= 54) {
            HashMap hashMap2 = new HashMap();
            hashMap2.put("stepTarget", Integer.valueOf((bArr[0] & 255) + ((bArr[1] & 255) << 8) + ((bArr[2] & 255) << 16)));
            hashMap2.put("calorTarget", Integer.valueOf((bArr[3] & 255) + ((bArr[4] & 255) << 8) + ((bArr[5] & 255) << 16)));
            hashMap2.put("distanceTarget", Integer.valueOf((bArr[6] & 255) + ((bArr[7] & 255) << 8) + ((bArr[8] & 255) << 16)));
            hashMap2.put("sleepTarget", Integer.valueOf((bArr[9] & 255) + ((bArr[10] & 255) << 8)));
            hashMap2.put("userHeight", Integer.valueOf(bArr[11] & 255));
            hashMap2.put("userWeight", Integer.valueOf(bArr[12] & 255));
            hashMap2.put("userSex", Integer.valueOf(bArr[13] & 255));
            hashMap2.put("userAge", Integer.valueOf(bArr[14] & 255));
            hashMap2.put("distanceUnit", Integer.valueOf(bArr[15] & 255));
            hashMap2.put("weightUnit", Integer.valueOf(bArr[16] & 255));
            hashMap2.put("tempUnit", Integer.valueOf(bArr[17] & 255));
            hashMap2.put("timeUnit", Integer.valueOf(bArr[18] & 255));
            hashMap2.put("longSitStartHour1", Integer.valueOf(bArr[19] & 255));
            hashMap2.put("longSitStartMin1", Integer.valueOf(bArr[20] & 255));
            hashMap2.put("longSitEndHour1", Integer.valueOf(bArr[21] & 255));
            hashMap2.put("longSitEndMin1", Integer.valueOf(bArr[22] & 255));
            hashMap2.put("longSitStartHour2", Integer.valueOf(bArr[23] & 255));
            hashMap2.put("longSitStartMin2", Integer.valueOf(bArr[24] & 255));
            hashMap2.put("longSitEndHour2", Integer.valueOf(bArr[25] & 255));
            hashMap2.put("longSitEndMin2", Integer.valueOf(bArr[26] & 255));
            hashMap2.put("longSitInterval", Integer.valueOf(bArr[27] & 255));
            hashMap2.put("longSitRepeat", Integer.valueOf(bArr[28] & 255));
            hashMap2.put("antiLostType", Integer.valueOf(bArr[29] & 255));
            hashMap2.put("antiLostRssi", Integer.valueOf(bArr[30] & 255));
            hashMap2.put("antiLostDelay", Integer.valueOf(bArr[31] & 255));
            hashMap2.put("antiLostDisDelay", Integer.valueOf(bArr[32] & 255));
            hashMap2.put("antiLostRepeat", Integer.valueOf(bArr[33] & 255));
            hashMap2.put("messageTotalSwitch", Integer.valueOf(bArr[34] & 255));
            hashMap2.put("messageSwitch0", Integer.valueOf(bArr[35] & 255));
            hashMap2.put("messageSwitch1", Integer.valueOf(bArr[36] & 255));
            hashMap2.put("heartHand", Integer.valueOf(bArr[37] & 255));
            hashMap2.put("heartAlarmSwitch", Integer.valueOf(bArr[38] & 255));
            hashMap2.put("heartAlarmValue", Integer.valueOf(bArr[39] & 255));
            hashMap2.put("heartMonitorTye", Integer.valueOf(bArr[40] & 255));
            hashMap2.put("heartMonitorInterval", Integer.valueOf(bArr[41] & 255));
            hashMap2.put("language", Integer.valueOf(bArr[42] & 255));
            hashMap2.put("handupswitch", Integer.valueOf(bArr[43] & 255));
            hashMap2.put("screenval", Integer.valueOf(bArr[44] & 255));
            hashMap2.put("skincolour", Integer.valueOf(bArr[45] & 255));
            hashMap2.put("screendown", Integer.valueOf(bArr[46] & 255));
            hashMap2.put("bluebreakswitch", Integer.valueOf(bArr[47] & 255));
            hashMap2.put("datauploadswitch", Integer.valueOf(bArr[48] & 255));
            hashMap2.put("disturbswitch", Integer.valueOf(bArr[49] & 255));
            hashMap2.put("disturbbegintimehour", Integer.valueOf(bArr[50] & 255));
            hashMap2.put("disturbbegintimemin", Integer.valueOf(bArr[51] & 255));
            hashMap2.put("disturbendtimehour", Integer.valueOf(bArr[52] & 255));
            hashMap2.put("disturbendtimemin", Integer.valueOf(bArr[53] & 255));
            if (bArr.length >= 65) {
                hashMap2.put("sleepswitch", Integer.valueOf(bArr[54] & 255));
                hashMap2.put("sleeptimehour", Integer.valueOf(bArr[55] & 255));
                hashMap2.put("sleeptimemin", Integer.valueOf(bArr[56] & 255));
                hashMap2.put("scheduleswitch", Integer.valueOf(bArr[57] & 255));
                hashMap2.put("eventswitch", Integer.valueOf(bArr[58] & 255));
                hashMap2.put("accidentswitch", Integer.valueOf(bArr[59] & 255));
                hashMap2.put("tempswitch", Integer.valueOf(bArr[60] & 255));
            }
            hashMap.put("data", hashMap2);
        }
        return hashMap;
    }

    public static HashMap unpackDialInfo(byte[] bArr) {
        if (bArr.length < 3) {
            return null;
        }
        int i2 = (bArr[0] & 255) - (YCBTClient.isSupportFunction(Constants.FunctionConstant.ISHASCUSTOMDIAL) ? 1 : 0);
        int i3 = bArr[1] & 255;
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        int i4 = 2;
        while (i4 < bArr.length - 5) {
            int i5 = i4 + 1;
            int i6 = bArr[i4] & 255;
            int i7 = i5 + 1;
            int i8 = bArr[i5] & 255;
            int i9 = i7 + 1;
            int i10 = bArr[i7] & 255;
            int i11 = i9 + 1;
            int i12 = bArr[i9] & 255;
            DialsBean dialsBean = new DialsBean();
            dialsBean.dialplateId = i6 + (i8 << 8) + (i10 << 16) + (i12 << 24);
            int i13 = i11 + 1;
            int i14 = i13 + 1;
            dialsBean.blockNumber = (bArr[i11] & 255) + ((bArr[i13] & 255) << 8);
            int i15 = i14 + 1;
            dialsBean.isCanDelete = (bArr[i14] & 255) == 1;
            int i16 = i15 + 1;
            dialsBean.dialVersion = (bArr[i15] & 255) + ((bArr[i16] & 255) << 8);
            if (i12 == 127 && i8 == 255 && i10 == 255) {
                arrayList2.add(dialsBean);
            } else {
                arrayList.add(dialsBean);
            }
            i4 = i16 + 1;
        }
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", 2307);
        hashMap.put("maxDials", Integer.valueOf(i2));
        hashMap.put("currDials", Integer.valueOf(i3));
        hashMap.put("dials", arrayList);
        hashMap.put("customDials", arrayList2);
        return hashMap;
    }

    public static HashMap unpackEcgLocation(byte[] bArr) {
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("ecgLocation", Integer.valueOf(bArr.length > 0 ? bArr[0] & 255 : 0));
        hashMap.put("dataType", 522);
        return hashMap;
    }

    public static HashMap<String, Object> unpackFileCount(byte[] bArr) {
        HashMap<String, Object> hashMap = new HashMap<>();
        hashMap.put(AlbumLoader.COLUMN_COUNT, Integer.valueOf((bArr[0] & 255) + ((bArr[1] & 255) << 8)));
        return hashMap;
    }

    public static HashMap<String, Object> unpackFileData(byte[] bArr) {
        HashMap<String, Object> hashMap = new HashMap<>();
        hashMap.put("total_size", Integer.valueOf((bArr[0] & 255) + ((bArr[1] & 255) << 8) + ((bArr[2] & 255) << 16) + ((bArr[3] & 255) << 24)));
        hashMap.put("total_package", Integer.valueOf((bArr[4] & 255) + ((bArr[5] & 255) << 8) + ((bArr[6] & 255) << 16) + ((bArr[7] & 255) << 24)));
        hashMap.put("verify_code", Integer.valueOf((bArr[8] & 255) + ((bArr[9] & 255) << 8) + ((bArr[10] & 255) << 16) + ((bArr[11] & 255) << 24)));
        return hashMap;
    }

    public static HashMap<String, Object> unpackFileList(byte[] bArr) {
        HashMap<String, Object> hashMap = new HashMap<>();
        hashMap.put("code", 0);
        ArrayList arrayList = new ArrayList();
        if (bArr != null && bArr.length >= 4) {
            int length = bArr.length / 24;
            int i2 = 0;
            int i3 = 0;
            while (i2 < length) {
                HashMap hashMap2 = new HashMap();
                byte[] bArr2 = new byte[16];
                System.arraycopy(bArr, i3, bArr2, 0, 16);
                int i4 = i3 + 16;
                hashMap2.put("file_name", new String(bArr2));
                int i5 = i4 + 1;
                int i6 = i5 + 1;
                int i7 = (bArr[i4] & 255) + ((bArr[i5] & 255) << 8);
                int i8 = i6 + 1;
                int i9 = i7 + ((bArr[i6] & 255) << 16);
                int i10 = i8 + 1;
                hashMap2.put("file_size", Integer.valueOf(i9 + ((bArr[i8] & 255) << 24)));
                int i11 = i10 + 1;
                int i12 = bArr[i10] & 255;
                int i13 = i11 + 1;
                int i14 = i12 + ((bArr[i11] & 255) << 8);
                int i15 = i13 + 1;
                hashMap2.put("file_verify", Integer.valueOf(i14 + ((bArr[i13] & 255) << 16) + ((bArr[i15] & 255) << 24)));
                arrayList.add(hashMap2);
                i2++;
                i3 = i15 + 1;
            }
        }
        hashMap.put("data", arrayList);
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.GetLaserTreatmentParams));
        return hashMap;
    }

    public static HashMap<String, Object> unpackFileSync(byte[] bArr) {
        HashMap<String, Object> hashMap = new HashMap<>();
        hashMap.put("data", bArr);
        return hashMap;
    }

    public static HashMap<String, Object> unpackFileSyncVerify(byte[] bArr) {
        HashMap<String, Object> hashMap = new HashMap<>();
        hashMap.put("package", Integer.valueOf((bArr[0] & 255) + ((bArr[1] & 255) << 8) + ((bArr[2] & 255) << 16) + ((bArr[3] & 255) << 24)));
        hashMap.put("size", Integer.valueOf((bArr[4] & 255) + ((bArr[5] & 255) << 8) + ((bArr[6] & 255) << 16) + ((bArr[7] & 255) << 24)));
        hashMap.put("crc", Integer.valueOf((bArr[8] & 255) + ((bArr[9] & 255) << 8)));
        return hashMap;
    }

    public static HashMap unpackGetALiIOTActivationState(byte[] bArr) {
        HashMap hashMap = new HashMap();
        int i2 = 0;
        if (bArr != null && bArr.length >= 1) {
            i2 = bArr[0] & 255;
        }
        hashMap.put(ServerProtocol.DIALOG_PARAM_STATE, Integer.valueOf(i2));
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.GetALiIOTActivationState));
        return hashMap;
    }

    public static HashMap unpackGetAllRealDataFromDevice(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null) {
            int i2 = 21;
            if (bArr.length >= 21) {
                hashMap.put("heartRate", Integer.valueOf(bArr[0] & 255));
                hashMap.put("SBP", Integer.valueOf(bArr[1] & 255));
                hashMap.put("DBP", Integer.valueOf(bArr[2] & 255));
                hashMap.put("bloodOxygen", Integer.valueOf(bArr[3] & 255));
                hashMap.put("respirationRate", Integer.valueOf(bArr[4] & 255));
                hashMap.put("tempIntValue", Integer.valueOf(bArr[5] & 255));
                hashMap.put("tempFloatValue", Integer.valueOf(bArr[6] & 255));
                hashMap.put("realSteps", Integer.valueOf((bArr[7] & 255) + ((bArr[8] & 255) << 8) + ((bArr[9] & 255) << 16)));
                hashMap.put("realCalories", Integer.valueOf((bArr[10] & 255) + ((bArr[11] & 255) << 8)));
                hashMap.put("realDistance", Integer.valueOf((bArr[12] & 255) + ((bArr[13] & 255) << 8)));
                hashMap.put("sportsRealSteps", Integer.valueOf((bArr[14] & 255) + ((bArr[15] & 255) << 8) + ((bArr[16] & 255) << 16)));
                hashMap.put("sportsRealCalories", Integer.valueOf((bArr[17] & 255) + ((bArr[18] & 255) << 8)));
                hashMap.put("sportsRealDistance", Integer.valueOf((bArr[19] & 255) + ((bArr[20] & 255) << 8)));
                if (bArr.length >= 26) {
                    hashMap.put("recordTime", Integer.valueOf((bArr[21] & 255) + ((bArr[22] & 255) << 8) + ((bArr[23] & 255) << 16) + ((bArr[24] & 255) << 24)));
                    i2 = 25;
                }
                if (bArr.length >= 30) {
                    int i3 = i2 + 1;
                    int i4 = i3 + 1;
                    hashMap.put("ppi", Integer.valueOf((bArr[i2] & 255) + ((bArr[i3] & 255) << 8) + ((bArr[i4] & 255) << 16) + ((bArr[i4 + 1] & 255) << 24)));
                }
            }
        }
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.GetAllRealDataFromDevice));
        return hashMap;
    }

    public static HashMap unpackGetCardInfo(byte[] bArr) {
        HashMap hashMap = new HashMap();
        hashMap.put("type", Integer.valueOf(bArr[0] & 255));
        byte[] bArr2 = new byte[bArr.length - 2];
        System.arraycopy(bArr, 1, bArr2, 0, bArr.length - 2);
        try {
            hashMap.put("card", new String(bArr2, StandardCharsets.UTF_8));
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.GetCardInfo));
        return hashMap;
    }

    public static HashMap unpackGetChipScheme(byte[] bArr) {
        int i2;
        HashMap hashMap = new HashMap();
        if (bArr == null || bArr.length < 1 || (i2 = bArr[0] & 255) >= 240) {
            hashMap.put("chipScheme", 0);
            SPUtil.saveChipScheme(0);
        } else {
            hashMap.put("chipScheme", Integer.valueOf(i2));
            SPUtil.saveChipScheme(i2);
            if (YCBTClientImpl.getInstance().connectState() == 9 && (i2 == 3 || i2 == 4)) {
                WatchManager.getInstance().initWatchManager(BleHelper.getHelper().getBleContext());
            }
        }
        hashMap.put("dataType", 539);
        return hashMap;
    }

    public static HashMap unpackGetCurrentAmbientLightIntensity(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null && bArr.length >= 3) {
            hashMap.put("ambientLightIntensityIsTest", Integer.valueOf(bArr[0] & 255));
            hashMap.put("ambientLightIntensityValue", Integer.valueOf((bArr[1] & 255) + ((bArr[2] & 255) << 8)));
        }
        hashMap.put("dataType", 530);
        return hashMap;
    }

    public static HashMap unpackGetCurrentAmbientTempAndHumidity(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null && bArr.length >= 5) {
            hashMap.put("ambientTempAndHumidityIsTest", Integer.valueOf(bArr[0] & 255));
            hashMap.put("ambientTempValue", (bArr[1] & 255) + "." + (bArr[2] & 255));
            hashMap.put("ambientHumidityValue", (bArr[3] & 255) + "." + (bArr[4] & 255));
        }
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.GetCurrentAmbientTempAndHumidity));
        return hashMap;
    }

    public static HashMap unpackGetCurrentSystemWorkingMode(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null && bArr.length >= 1) {
            hashMap.put("currentSystemWorkingMode", Integer.valueOf(bArr[0] & 255));
        }
        hashMap.put("dataType", 534);
        return hashMap;
    }

    public static HashMap unpackGetDeviceRemindInfo(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null && bArr.length >= 1) {
            hashMap.put("deviceRemindInfo", Integer.valueOf(bArr[0] & 255));
        }
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.GetDeviceRemindInfo));
        return hashMap;
    }

    public static HashMap unpackGetEcgMode(byte[] bArr) {
        HashMap hashMap = new HashMap();
        hashMap.put("ecgMode", Integer.valueOf(bArr.length >= 1 ? bArr[0] & 255 : 0));
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.GetEcgMode));
        return hashMap;
    }

    public static HashMap unpackGetEventReminder(byte[] bArr) {
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Real_UploadEventReminder));
        if (bArr != null && bArr.length >= 7) {
            hashMap.put("eventReminderIndex", Integer.valueOf(bArr[0] & 255));
            hashMap.put("eventReminderSwitch", Integer.valueOf(bArr[1] & 255));
            hashMap.put("eventReminderType", Integer.valueOf(bArr[2] & 255));
            hashMap.put("eventReminderHour", Integer.valueOf(bArr[3] & 255));
            hashMap.put("eventReminderMin", Integer.valueOf(bArr[4] & 255));
            hashMap.put("eventReminderRepeat", Integer.valueOf(bArr[5] & 255));
            hashMap.put("eventReminderInterval", Integer.valueOf(bArr[6] & 255));
            if ((bArr[2] & 255) != 1 || bArr.length <= 7) {
                hashMap.put("incidentName", "");
            } else {
                byte[] bArr2 = new byte[bArr.length - 7];
                System.arraycopy(bArr, 7, bArr2, 0, bArr.length - 7);
                try {
                    hashMap.put("incidentName", new String(bArr2, "utf-8"));
                } catch (Exception e2) {
                    e2.printStackTrace();
                }
            }
        }
        return hashMap;
    }

    public static HashMap unpackGetHeavenEarthAndFiveElement(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null && bArr.length >= 1) {
            try {
                hashMap.put("data", new String(bArr, "utf-8"));
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.GetHeavenEarthAndFiveElement));
        return hashMap;
    }

    public static HashMap unpackGetHistoryOutline(byte[] bArr) {
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10;
        HashMap hashMap = new HashMap();
        int i11 = 0;
        hashMap.put("code", 0);
        if (bArr.length > 8) {
            i3 = bArr[0] & 255;
            i4 = (bArr[1] & 255) + ((bArr[2] & 255) << 8);
            i5 = (bArr[3] & 255) + ((bArr[4] & 255) << 8);
            i6 = (bArr[5] & 255) + ((bArr[6] & 255) << 8);
            i7 = (bArr[7] & 255) + ((bArr[8] & 255) << 8);
            if (bArr.length > 16) {
                i11 = (bArr[9] & 255) + ((bArr[10] & 255) << 8);
                i8 = (bArr[11] & 255) + ((bArr[12] & 255) << 8);
                i9 = (bArr[13] & 255) + ((bArr[14] & 255) << 8);
                i10 = (bArr[15] & 255) + ((bArr[16] & 255) << 8);
            } else {
                i8 = 0;
                i9 = 0;
                i10 = 0;
            }
            hashMap.put("supportOk", 1);
            i2 = i11;
            i11 = i10;
        } else {
            hashMap.put("supportOk", 0);
            i2 = 0;
            i3 = 0;
            i4 = 0;
            i5 = 0;
            i6 = 0;
            i7 = 0;
            i8 = 0;
            i9 = 0;
        }
        hashMap.put("SleepNum", Integer.valueOf(i3));
        hashMap.put("SleepTotalTime", Integer.valueOf(i4));
        hashMap.put("HeartNum", Integer.valueOf(i5));
        hashMap.put("SportNum", Integer.valueOf(i6));
        hashMap.put("BloodNum", Integer.valueOf(i7));
        hashMap.put("BloodOxygenNum", Integer.valueOf(i2));
        hashMap.put("TempHumidNum", Integer.valueOf(i8));
        hashMap.put("TempNum", Integer.valueOf(i9));
        hashMap.put("AmbientLightNum", Integer.valueOf(i11));
        hashMap.put("dataType", 525);
        return hashMap;
    }

    public static HashMap unpackGetInflatedBlood(byte[] bArr) {
        HashMap hashMap = new HashMap();
        ArrayList arrayList = new ArrayList();
        if (bArr != null && bArr.length >= 4) {
            int length = bArr.length / 4;
            int i2 = 0;
            int i3 = 0;
            while (i2 < length) {
                HashMap hashMap2 = new HashMap();
                int i4 = i3 + 1;
                int i5 = i4 + 1;
                hashMap2.put("pressureValue", Integer.valueOf((bArr[i3] & 255) + ((bArr[i4] & 255) << 8)));
                int i6 = i5 + 1;
                hashMap2.put("signalValue", Integer.valueOf((bArr[i5] & 255) + ((bArr[i6] & 255) << 8)));
                arrayList.add(hashMap2);
                i2++;
                i3 = i6 + 1;
            }
        }
        hashMap.put("data", arrayList);
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Real_UploadInflatedBlood));
        return hashMap;
    }

    public static HashMap unpackGetInsuranceRelatedInfo(byte[] bArr) {
        Object valueOf;
        HashMap hashMap = new HashMap();
        if (bArr != null && bArr.length >= 2) {
            switch (bArr[0] & 255) {
                case 0:
                    byte[] bArr2 = new byte[bArr.length - 1];
                    System.arraycopy(bArr, 1, bArr2, 0, bArr.length - 1);
                    try {
                        hashMap.put("data", new String(bArr2, "utf-8"));
                        break;
                    } catch (Exception e2) {
                        e2.printStackTrace();
                        break;
                    }
                case 1:
                case 2:
                case 3:
                case 4:
                    if (bArr.length >= 5) {
                        valueOf = Integer.valueOf((bArr[1] & 255) + ((bArr[2] & 255) << 8) + ((bArr[3] & 255) << 16) + ((bArr[4] & 255) << 24));
                        hashMap.put("data", valueOf);
                        break;
                    }
                    break;
                case 5:
                case 6:
                    valueOf = Integer.valueOf(bArr[1] & 255);
                    hashMap.put("data", valueOf);
                    break;
                case 7:
                    valueOf = Long.valueOf(((bArr[1] & 255) + ((bArr[2] & 255) << 8) + ((bArr[3] & 255) << 16) + ((bArr[4] & 255) << 24) + YCBTClient.SecFrom30Year) * 1000);
                    hashMap.put("data", valueOf);
                    break;
            }
            hashMap.put("type", Integer.valueOf(bArr[0] & 255));
        }
        hashMap.put("dataType", 535);
        return hashMap;
    }

    public static HashMap unpackGetLaserTreatmentParams(byte[] bArr) {
        HashMap hashMap = new HashMap();
        ArrayList arrayList = new ArrayList();
        if (bArr != null && bArr.length >= 10) {
            int length = bArr.length / 10;
            int i2 = 0;
            int i3 = 0;
            while (i2 < length) {
                HashMap hashMap2 = new HashMap();
                int i4 = i3 + 1;
                hashMap2.put("id", Integer.valueOf(bArr[i3] & 255));
                int i5 = i4 + 1;
                hashMap2.put("onOff", Integer.valueOf(bArr[i4] & 255));
                int i6 = i5 + 1;
                hashMap2.put("startHour", Integer.valueOf(bArr[i5] & 255));
                int i7 = i6 + 1;
                hashMap2.put("startMin", Integer.valueOf(bArr[i6] & 255));
                int i8 = i7 + 1;
                hashMap2.put("endHour", Integer.valueOf(bArr[i7] & 255));
                int i9 = i8 + 1;
                hashMap2.put("endMin", Integer.valueOf(bArr[i8] & 255));
                int i10 = i9 + 1;
                int i11 = i10 + 1;
                hashMap2.put("measuringFrequency", Integer.valueOf((bArr[i9] & 255) + ((bArr[i10] & 255) << 8)));
                int i12 = i11 + 1;
                hashMap2.put("laserIntensity", Integer.valueOf(bArr[i11] & 255));
                hashMap2.put("laserDuration", Integer.valueOf(bArr[i12] & 255));
                arrayList.add(hashMap2);
                i2++;
                i3 = i12 + 1;
            }
        }
        hashMap.put("data", arrayList);
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.GetLaserTreatmentParams));
        return hashMap;
    }

    public static HashMap unpackGetMeasurementFunction(byte[] bArr) {
        HashMap hashMap = new HashMap();
        byte b2 = bArr[0];
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.GetMeasurementFunction));
        hashMap.put("bloodSugar", Integer.valueOf(b2 & 1));
        hashMap.put("uricAcid", Integer.valueOf((b2 >> 1) & 1));
        hashMap.put("bloodFat", Integer.valueOf((b2 >> 2) & 1));
        String byteToBinary = byteToBinary(bArr[0]);
        SPUtil.put(Constants.SharedKey.Function_Str, byteToBinary);
        YCBTLog.e("获取功能：" + byteToBinary);
        return hashMap;
    }

    public static HashMap unpackGetNowSport(byte[] bArr) {
        int i2;
        int i3;
        HashMap hashMap = new HashMap();
        int i4 = 0;
        hashMap.put("code", 0);
        if (bArr.length > 6) {
            int i5 = (bArr[0] & 255) + ((bArr[1] & 255) << 8) + ((bArr[2] & 255) << 16);
            i3 = (bArr[3] & 255) + ((bArr[4] & 255) << 8);
            int i6 = ((bArr[6] & 255) << 8) + (bArr[5] & 255);
            YCBTLog.e("tStep " + i5 + " tCal " + i3 + " tDis " + i6);
            hashMap.put("supportOk", 1);
            i4 = i6;
            i2 = i5;
        } else {
            hashMap.put("supportOk", 0);
            i2 = 0;
            i3 = 0;
        }
        hashMap.put("nowStep", Integer.valueOf(i2));
        hashMap.put("nowCalorie", Integer.valueOf(i3));
        hashMap.put("nowDistance", Integer.valueOf(i4));
        hashMap.put("dataType", 524);
        return hashMap;
    }

    public static HashMap unpackGetPowerStatistics(byte[] bArr) {
        int offset = TimeZone.getDefault().getOffset(System.currentTimeMillis());
        HashMap hashMap = new HashMap();
        long j2 = bArr[28] & 255;
        long j3 = bArr[29] & 255;
        hashMap.put("lastChargingTime", Long.valueOf(((((((bArr[0] & 255) + ((bArr[1] & 255) << 8)) + ((bArr[2] & 255) << 16)) + ((bArr[3] & 255) << 24)) + 946684800) * 1000) - offset));
        hashMap.put("usageTime", Long.valueOf((bArr[4] & 255) + ((bArr[5] & 255) << 8) + ((bArr[6] & 255) << 16) + ((bArr[7] & 255) << 24)));
        hashMap.put("screenDuration", Long.valueOf((bArr[8] & 255) + ((bArr[9] & 255) << 8) + ((bArr[10] & 255) << 16) + ((bArr[11] & 255) << 24)));
        hashMap.put("callDuration", Long.valueOf((bArr[12] & 255) + ((bArr[13] & 255) << 8) + ((bArr[14] & 255) << 16) + ((bArr[15] & 255) << 24)));
        hashMap.put("musicDuration", Long.valueOf((bArr[16] & 255) + ((bArr[17] & 255) << 8) + ((bArr[18] & 255) << 16) + ((bArr[19] & 255) << 24)));
        hashMap.put("healthMeasurementDuration", Long.valueOf((bArr[20] & 255) + ((bArr[21] & 255) << 8) + ((bArr[22] & 255) << 16) + ((bArr[23] & 255) << 24)));
        hashMap.put("messagesNumber", Long.valueOf((bArr[24] & 255) + ((bArr[25] & 255) << 8) + ((bArr[26] & 255) << 16) + ((bArr[27] & 255) << 24)));
        hashMap.put("lastChargingEndBattery", Long.valueOf(j2));
        hashMap.put("batteryLevel", Long.valueOf(j3));
        hashMap.put("aratedBloodPressure", Long.valueOf((bArr[30] & 255) + ((bArr[31] & 255) << 8) + ((bArr[32] & 255) << 16) + ((bArr[33] & 255) << 24)));
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.GetPowerStatistics));
        return hashMap;
    }

    public static HashMap unpackGetRealBloodOxygen(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null && bArr.length >= 2) {
            hashMap.put("bloodOxygenIsTest", Integer.valueOf(bArr[0] & 255));
            hashMap.put("bloodOxygenValue", Integer.valueOf(bArr[1] & 255));
        }
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.GetRealBloodOxygen));
        return hashMap;
    }

    public static HashMap unpackGetRealTemp(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null && bArr.length > 1) {
            hashMap.put("tempValue", (bArr[0] & 255) + "." + (bArr[1] & 255));
        }
        hashMap.put("dataType", 526);
        return hashMap;
    }

    public static HashMap unpackGetScheduleInfo(byte[] bArr) {
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Real_UploadSchedule));
        if (bArr != null && bArr.length >= 9) {
            hashMap.put("scheduleIndex", Integer.valueOf(bArr[0] & 255));
            hashMap.put("scheduleEnable", Integer.valueOf(bArr[1] & 255));
            hashMap.put("incidentIndex", Integer.valueOf(bArr[2] & 255));
            hashMap.put("incidentEnable", Integer.valueOf(bArr[3] & 255));
            hashMap.put("incidentTime", Long.valueOf(((((((bArr[4] & 255) + ((bArr[5] & 255) << 8)) + ((bArr[6] & 255) << 16)) + ((bArr[7] & 255) << 24)) + YCBTClient.SecFrom30Year) * 1000) - TimeZone.getDefault().getOffset(System.currentTimeMillis())));
            hashMap.put("incidentID", Integer.valueOf(bArr[8] & 255));
            if (bArr.length > 9) {
                byte[] bArr2 = new byte[bArr.length - 9];
                System.arraycopy(bArr, 9, bArr2, 0, bArr.length - 9);
                try {
                    hashMap.put("incidentName", new String(bArr2, "utf-8"));
                } catch (Exception e2) {
                    e2.printStackTrace();
                }
            } else {
                hashMap.put("incidentName", "");
            }
        }
        return hashMap;
    }

    public static HashMap unpackGetScreenInfo(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null && bArr.length >= 4) {
            hashMap.put("currentScreenDisplayLevel", Integer.valueOf(bArr[0] & 255));
            hashMap.put("currentScreenOffTime", Integer.valueOf(bArr[1] & 255));
            hashMap.put("currentLanguageSettings", Integer.valueOf(bArr[2] & 255));
            hashMap.put("CurrentWorkingMode", Integer.valueOf(bArr[3] & 255));
        }
        hashMap.put("dataType", 527);
        return hashMap;
    }

    public static HashMap unpackGetScreenParameters(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null && bArr.length >= 7) {
            hashMap.put("screenType", Integer.valueOf(bArr[0] & 255));
            hashMap.put("screenWidth", Integer.valueOf((bArr[1] & 255) + ((bArr[2] & 255) << 8)));
            hashMap.put("screenHeight", Integer.valueOf((bArr[3] & 255) + ((bArr[4] & 255) << 8)));
            hashMap.put("screenCorner", Integer.valueOf((bArr[5] & 255) + ((bArr[6] & 255) << 8)));
            if (bArr.length >= 13) {
                hashMap.put("screenCpWidth", Integer.valueOf((bArr[7] & 255) + ((bArr[8] & 255) << 8)));
                hashMap.put("screenCpHeight", Integer.valueOf((bArr[9] & 255) + ((bArr[10] & 255) << 8)));
                hashMap.put("screenCpCorner", Integer.valueOf((bArr[11] & 255) + ((bArr[12] & 255) << 8)));
            }
        }
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.GetScreenParameters));
        return hashMap;
    }

    public static HashMap unpackGetSensorSamplingInfo(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null && bArr.length >= 5) {
            hashMap.put("sensorSamplingInfoState", Integer.valueOf(bArr[0] & 255));
            hashMap.put("sensorSamplingInfoDuration", Integer.valueOf((bArr[1] & 255) + ((bArr[2] & 255) << 8)));
            hashMap.put("sensorSamplingInfoInterval", Integer.valueOf((bArr[3] & 255) + ((bArr[4] & 255) << 8)));
        }
        hashMap.put("dataType", 533);
        return hashMap;
    }

    public static HashMap unpackGetSleepStatus(byte[] bArr) {
        HashMap hashMap = new HashMap();
        hashMap.put("sleepStatus", Integer.valueOf(bArr.length >= 1 ? bArr[0] & 255 : 0));
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.GetSleepStatus));
        return hashMap;
    }

    public static HashMap unpackGetStatusOfManualMode(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null && bArr.length >= 1) {
            hashMap.put("statusOfManualMode", Integer.valueOf(bArr[0] & 255));
        }
        hashMap.put("dataType", 537);
        return hashMap;
    }

    public static HashMap unpackGetUploadConfigurationInfoOfReminder(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null && bArr.length >= 2) {
            hashMap.put("UploadConfigurationInfoOfReminderEnable", Integer.valueOf(bArr[0] & 255));
            hashMap.put("UploadConfigurationInfoOfReminderValue", Integer.valueOf(bArr[1] & 255));
        }
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.GetUploadConfigurationInfoOfReminder));
        return hashMap;
    }

    public static HashMap unpackGetUploadOGA(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null) {
            int i2 = 21;
            if (bArr.length >= 21) {
                hashMap.put("heartRate", Integer.valueOf(bArr[0] & 255));
                hashMap.put("SBP", Integer.valueOf(bArr[1] & 255));
                hashMap.put("DBP", Integer.valueOf(bArr[2] & 255));
                hashMap.put("bloodOxygen", Integer.valueOf(bArr[3] & 255));
                hashMap.put("respirationRate", Integer.valueOf(bArr[4] & 255));
                hashMap.put("tempIntValue", Integer.valueOf(bArr[5] & 255));
                hashMap.put("tempFloatValue", Integer.valueOf(bArr[6] & 255));
                hashMap.put("realSteps", Integer.valueOf((bArr[7] & 255) + ((bArr[8] & 255) << 8) + ((bArr[9] & 255) << 16)));
                hashMap.put("realCalories", Integer.valueOf((bArr[10] & 255) + ((bArr[11] & 255) << 8)));
                hashMap.put("realDistance", Integer.valueOf((bArr[12] & 255) + ((bArr[13] & 255) << 8)));
                hashMap.put("sportsRealSteps", Integer.valueOf((bArr[14] & 255) + ((bArr[15] & 255) << 8) + ((bArr[16] & 255) << 16)));
                hashMap.put("sportsRealCalories", Integer.valueOf((bArr[17] & 255) + ((bArr[18] & 255) << 8)));
                hashMap.put("sportsRealDistance", Integer.valueOf((bArr[19] & 255) + ((bArr[20] & 255) << 8)));
                if (bArr.length >= 26) {
                    hashMap.put("recordTime", Integer.valueOf((bArr[21] & 255) + ((bArr[22] & 255) << 8) + ((bArr[23] & 255) << 16) + ((bArr[24] & 255) << 24)));
                    i2 = 25;
                }
                if (bArr.length >= 30) {
                    int i3 = i2 + 1;
                    int i4 = i3 + 1;
                    int i5 = (bArr[i2] & 255) + ((bArr[i3] & 255) << 8);
                    int i6 = i4 + 1;
                    hashMap.put("ppi", Integer.valueOf(i5 + ((bArr[i4] & 255) << 16) + ((bArr[i6] & 255) << 24)));
                    i2 = i6 + 1;
                }
                if (bArr.length >= 31) {
                    hashMap.put("maximalOxygenIntake", Integer.valueOf(bArr[i2] & 255));
                }
            }
        }
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Real_UploadOGA));
        return hashMap;
    }

    public static HashMap unpackHealthData(byte[] bArr, int i2) {
        HashMap hashMap;
        String str;
        int i3;
        ArrayList arrayList;
        int i4;
        int i5;
        int i6;
        ArrayList arrayList2;
        int i7;
        HashMap hashMap2;
        String str2;
        ArrayList arrayList3;
        int i8;
        ArrayList arrayList4;
        HashMap hashMap3;
        ArrayList arrayList5;
        int i9;
        byte[] bArr2 = bArr;
        int offset = TimeZone.getDefault().getOffset(System.currentTimeMillis());
        HashMap hashMap4 = new HashMap();
        int i10 = 0;
        hashMap4.put("code", 0);
        String str3 = "sportDistance";
        String str4 = "sportCalorie";
        String str5 = "data";
        long j2 = 1000;
        long j3 = 946684800;
        switch (i2) {
            case 2:
                hashMap = hashMap4;
                byte[] bArr3 = bArr2;
                str = "data";
                ArrayList arrayList6 = new ArrayList();
                int i11 = 0;
                while (i11 + 14 <= bArr3.length) {
                    int i12 = i11 + 1;
                    int i13 = i12 + 1;
                    int i14 = (bArr3[i11] & 255) + ((bArr3[i12] & 255) << 8);
                    int i15 = i14 + ((bArr3[i13] & 255) << 16);
                    int i16 = i13 + 1 + 1;
                    long j4 = (i15 + ((bArr3[r6] & 255) << 24) + 946684800) * 1000;
                    int i17 = i16 + 1;
                    int i18 = bArr3[i16] & 255;
                    int i19 = i17 + 1;
                    int i20 = i18 + ((bArr3[i17] & 255) << 8);
                    int i21 = i20 + ((bArr3[i19] & 255) << 16);
                    int i22 = i19 + 1 + 1;
                    long j5 = (i21 + ((bArr3[r6] & 255) << 24) + 946684800) * 1000;
                    int i23 = i22 + 1;
                    int i24 = bArr3[i22] & 255;
                    int i25 = i23 + 1;
                    int i26 = i24 + ((bArr3[i23] & 255) << 8);
                    int i27 = i25 + 1;
                    int i28 = i27 + 1;
                    int i29 = (bArr3[i25] & 255) + ((bArr3[i27] & 255) << 8);
                    int i30 = i28 + 1;
                    int i31 = (bArr3[i28] & 255) + ((bArr3[i30] & 255) << 8);
                    long j6 = offset;
                    long j7 = j4 - j6;
                    long j8 = j5 - j6;
                    HashMap hashMap5 = new HashMap();
                    hashMap5.put("sportStartTime", Long.valueOf(j7));
                    hashMap5.put("sportEndTime", Long.valueOf(j8));
                    hashMap5.put("sportStep", Integer.valueOf(i26));
                    hashMap5.put("sportCalorie", Integer.valueOf(i31));
                    hashMap5.put("sportDistance", Integer.valueOf(i29));
                    arrayList6.add(hashMap5);
                    bArr3 = bArr;
                    i11 = i30 + 1;
                }
                i3 = Constants.DATATYPE.Health_HistorySport;
                arrayList = arrayList6;
                hashMap.put("dataType", Integer.valueOf(i3));
                hashMap.put(str, arrayList);
                return hashMap;
            case 4:
                ArrayList arrayList7 = new ArrayList();
                int i32 = 0;
                int i33 = 0;
                int i34 = 0;
                while (i32 + 20 <= bArr2.length) {
                    int i35 = i32 + 1;
                    byte b2 = bArr2[i32];
                    int i36 = i35 + 1;
                    byte b3 = bArr2[i35];
                    int i37 = i36 + 1;
                    int i38 = i37 + 1;
                    int i39 = (bArr2[i36] & 255) + ((bArr2[i37] & 255) << 8);
                    int i40 = i38 + 1;
                    int i41 = i40 + 1;
                    int i42 = (bArr2[i38] & 255) + ((bArr2[i40] & 255) << 8);
                    int i43 = i42 + ((bArr2[i41] & 255) << 16);
                    int i44 = i41 + 1 + 1;
                    long j9 = (i43 + ((bArr2[r6] & 255) << 24) + 946684800) * 1000;
                    int i45 = i44 + 1;
                    int i46 = bArr2[i44] & 255;
                    int i47 = i45 + 1;
                    int i48 = i46 + ((bArr2[i45] & 255) << 8);
                    int i49 = i48 + ((bArr2[i47] & 255) << 16);
                    int i50 = i47 + 1 + 1;
                    long j10 = (i49 + ((bArr2[r6] & 255) << 24) + 946684800) * 1000;
                    int i51 = i50 + 1;
                    int i52 = bArr2[i50] & 255;
                    int i53 = i51 + 1;
                    int i54 = i52 + ((bArr2[i51] & 255) << 8);
                    if (i54 == 65535) {
                        int i55 = i53 + 1;
                        int i56 = bArr2[i53] & 255;
                        int i57 = i55 + 1;
                        i34 = ((bArr2[i55] & 255) << 8) + i56;
                        int i58 = i57 + 1;
                        int i59 = i58 + 1;
                        i4 = (bArr2[i57] & 255) + ((bArr2[i58] & 255) << 8);
                        int i60 = i59 + 1;
                        i5 = i60 + 1;
                        i6 = (bArr2[i59] & 255) + ((bArr2[i60] & 255) << 8);
                    } else {
                        int i61 = i53 + 1;
                        int i62 = bArr2[i53] & 255;
                        int i63 = i61 + 1;
                        i33 = ((bArr2[i61] & 255) << 8) + i62;
                        int i64 = i63 + 1;
                        int i65 = i64 + 1;
                        i4 = ((bArr2[i63] & 255) + ((bArr2[i64] & 255) << 8)) * 60;
                        int i66 = i65 + 1;
                        i5 = i66 + 1;
                        i6 = ((bArr2[i65] & 255) + ((bArr2[i66] & 255) << 8)) * 60;
                    }
                    ArrayList arrayList8 = new ArrayList();
                    ArrayList arrayList9 = new ArrayList();
                    int i67 = i5;
                    int i68 = 0;
                    int i69 = 0;
                    while (true) {
                        arrayList2 = arrayList7;
                        i7 = i34;
                        if ((i67 - i5) + 8 <= i39 - 20) {
                            int i70 = bArr2[i67] & 255;
                            int i71 = i39;
                            int i72 = i6;
                            int i73 = i67 + 1 + 1 + 1 + 1 + 1;
                            long j11 = ((bArr2[r0] & 255) + ((bArr2[r24] & 255) << 8) + ((bArr2[r28] & 255) << 16) + ((bArr2[r1] & 255) << 24) + 946684800) * 1000;
                            int i74 = i73 + 1;
                            int i75 = i74 + 1;
                            int i76 = i4;
                            int i77 = (bArr2[i73] & 255) + ((bArr2[i74] & 255) << 8);
                            i67 = i75 + 1;
                            int i78 = i77 + ((bArr2[i75] & 255) << 16);
                            if (i70 == 244) {
                                i69++;
                                i68 += i78;
                            }
                            int i79 = i54;
                            long j12 = j11 - offset;
                            if (!arrayList9.contains("" + j12)) {
                                HashMap hashMap6 = new HashMap();
                                hashMap6.put("sleepType", Integer.valueOf(i70));
                                hashMap6.put("sleepStartTime", Long.valueOf(j12));
                                hashMap6.put("sleepLen", Integer.valueOf(i78));
                                arrayList8.add(hashMap6);
                                arrayList9.add("" + j12);
                            }
                            arrayList7 = arrayList2;
                            i34 = i7;
                            i54 = i79;
                            i39 = i71;
                            i6 = i72;
                            i4 = i76;
                        }
                    }
                    HashMap hashMap7 = new HashMap();
                    long j13 = offset;
                    hashMap7.put("startTime", Long.valueOf(j9 - j13));
                    hashMap7.put("endTime", Long.valueOf(j10 - j13));
                    hashMap7.put("deepSleepCount", Integer.valueOf(i54));
                    hashMap7.put("lightSleepCount", Integer.valueOf(i33));
                    hashMap7.put("deepSleepTotal", Integer.valueOf(i4));
                    hashMap7.put("lightSleepTotal", Integer.valueOf(i6));
                    hashMap7.put("rapidEyeMovementTotal", Integer.valueOf(i7));
                    hashMap7.put("sleepData", arrayList8);
                    hashMap7.put("wakeCount", Integer.valueOf(i69));
                    hashMap7.put("wakeDuration", Integer.valueOf(i68));
                    arrayList2.add(hashMap7);
                    hashMap4.put("dataType", Integer.valueOf(Constants.DATATYPE.Health_HistorySleep));
                    hashMap4.put("data", arrayList2);
                    arrayList7 = arrayList2;
                    i32 = i67;
                    i34 = i7;
                }
                return hashMap4;
            case 6:
                hashMap2 = hashMap4;
                str2 = "data";
                arrayList3 = new ArrayList();
                while (i10 + 6 <= bArr2.length) {
                    int i80 = i10 + 1;
                    int i81 = i80 + 1;
                    int i82 = (bArr2[i10] & 255) + ((bArr2[i80] & 255) << 8);
                    int i83 = i82 + ((bArr2[i81] & 255) << 16);
                    int i84 = i81 + 1 + 1;
                    int i85 = i84 + 1;
                    i10 = i85 + 1;
                    int i86 = bArr2[i85] & 255;
                    HashMap hashMap8 = new HashMap();
                    hashMap8.put("heartStartTime", Long.valueOf((((i83 + ((bArr2[r0] & 255) << 24)) + 946684800) * 1000) - offset));
                    hashMap8.put("heartValue", Integer.valueOf(i86));
                    arrayList3.add(hashMap8);
                }
                i8 = Constants.DATATYPE.Health_HistoryHeart;
                i3 = i8;
                arrayList = arrayList3;
                hashMap = hashMap2;
                str = str2;
                hashMap.put("dataType", Integer.valueOf(i3));
                hashMap.put(str, arrayList);
                return hashMap;
            case 8:
                hashMap2 = hashMap4;
                str2 = "data";
                arrayList3 = new ArrayList();
                while (i10 + 8 <= bArr2.length) {
                    int i87 = i10 + 1;
                    int i88 = i87 + 1;
                    int i89 = (bArr2[i10] & 255) + ((bArr2[i87] & 255) << 8);
                    int i90 = i89 + ((bArr2[i88] & 255) << 16);
                    int i91 = i88 + 1 + 1;
                    int i92 = i91 + 1;
                    int i93 = bArr2[i91] & 255;
                    int i94 = i92 + 1;
                    int i95 = bArr2[i92] & 255;
                    int i96 = i94 + 1;
                    int i97 = bArr2[i94] & 255;
                    HashMap hashMap9 = new HashMap();
                    hashMap9.put("bloodStartTime", Long.valueOf((((i90 + ((bArr2[r0] & 255) << 24)) + 946684800) * 1000) - offset));
                    hashMap9.put("bloodSBP", Integer.valueOf(i95));
                    hashMap9.put("bloodDBP", Integer.valueOf(i97));
                    hashMap9.put("isInflated", Integer.valueOf(i93));
                    arrayList3.add(hashMap9);
                    i10 = i96 + 1;
                }
                i8 = Constants.DATATYPE.Health_HistoryBlood;
                i3 = i8;
                arrayList = arrayList3;
                hashMap = hashMap2;
                str = str2;
                hashMap.put("dataType", Integer.valueOf(i3));
                hashMap.put(str, arrayList);
                return hashMap;
            case 9:
                byte[] bArr4 = bArr2;
                hashMap2 = hashMap4;
                str2 = "data";
                ArrayList arrayList10 = new ArrayList();
                while (i10 + 20 <= bArr4.length) {
                    int i98 = i10 + 1;
                    int i99 = bArr4[i10] & 255;
                    int i100 = i98 + 1;
                    int i101 = i99 + ((bArr4[i98] & 255) << 8);
                    int i102 = i101 + ((bArr4[i100] & 255) << 16);
                    int i103 = i100 + 1 + 1;
                    long j14 = (i102 + ((bArr4[r1] & 255) << 24) + 946684800) * 1000;
                    int i104 = i103 + 1;
                    int i105 = i104 + 1;
                    int i106 = (bArr4[i103] & 255) + ((bArr4[i104] & 255) << 8);
                    int i107 = i105 + 1;
                    int i108 = bArr4[i105] & 255;
                    int i109 = i107 + 1;
                    int i110 = bArr4[i107] & 255;
                    int i111 = i109 + 1;
                    int i112 = bArr4[i109] & 255;
                    int i113 = i111 + 1;
                    int i114 = bArr4[i111] & 255;
                    int i115 = i113 + 1;
                    int i116 = bArr4[i113] & 255;
                    int i117 = i115 + 1;
                    int i118 = bArr4[i115] & 255;
                    int i119 = i117 + 1;
                    int i120 = bArr4[i117] & 255;
                    int i121 = i119 + 1;
                    ArrayList arrayList11 = arrayList10;
                    int i122 = bArr4[i119] & 255;
                    int i123 = i121 + 1;
                    int i124 = bArr4[i121] & 255;
                    HashMap hashMap10 = new HashMap();
                    hashMap10.put("startTime", Long.valueOf(j14 - offset));
                    hashMap10.put("stepValue", Integer.valueOf(i106));
                    hashMap10.put("heartValue", Integer.valueOf(i108));
                    hashMap10.put("DBPValue", Integer.valueOf(i112));
                    hashMap10.put("SBPValue", Integer.valueOf(i110));
                    hashMap10.put("OOValue", Integer.valueOf(i114));
                    hashMap10.put("respiratoryRateValue", Integer.valueOf(i116));
                    hashMap10.put("hrvValue", Integer.valueOf(i118));
                    hashMap10.put("cvrrValue", Integer.valueOf(i120));
                    hashMap10.put("tempIntValue", Integer.valueOf(i122));
                    hashMap10.put("tempFloatValue", Integer.valueOf(i124));
                    int i125 = i123 + 1;
                    bArr4 = bArr;
                    hashMap10.put("bodyFatIntValue", Integer.valueOf(bArr4[i123] & 255));
                    int i126 = i125 + 1;
                    hashMap10.put("bodyFatFloatValue", Integer.valueOf(bArr4[i125] & 255));
                    hashMap10.put("bloodSugarValue", Integer.valueOf(bArr4[i126] & 255));
                    arrayList11.add(hashMap10);
                    i10 = i126 + 1 + 2;
                    arrayList10 = arrayList11;
                }
                arrayList = arrayList10;
                i3 = 1289;
                hashMap = hashMap2;
                str = str2;
                hashMap.put("dataType", Integer.valueOf(i3));
                hashMap.put(str, arrayList);
                return hashMap;
            case 26:
                hashMap2 = hashMap4;
                str2 = "data";
                arrayList3 = new ArrayList();
                while (i10 + 6 <= bArr2.length) {
                    int i127 = i10 + 1;
                    int i128 = i127 + 1;
                    int i129 = (bArr2[i10] & 255) + ((bArr2[i127] & 255) << 8);
                    int i130 = i129 + ((bArr2[i128] & 255) << 16);
                    int i131 = i128 + 1 + 1;
                    int i132 = i131 + 1;
                    int i133 = bArr2[i131] & 255;
                    int i134 = i132 + 1;
                    int i135 = bArr2[i132] & 255;
                    HashMap hashMap11 = new HashMap();
                    hashMap11.put("startTime", Long.valueOf((((i130 + ((bArr2[r0] & 255) << 24)) + 946684800) * 1000) - offset));
                    hashMap11.put("type", Integer.valueOf(i133));
                    hashMap11.put("value", Integer.valueOf(i135));
                    arrayList3.add(hashMap11);
                    i10 = i134;
                }
                i8 = Constants.DATATYPE.Health_HistoryBloodOxygen;
                i3 = i8;
                arrayList = arrayList3;
                hashMap = hashMap2;
                str = str2;
                hashMap.put("dataType", Integer.valueOf(i3));
                hashMap.put(str, arrayList);
                return hashMap;
            case 28:
                hashMap2 = hashMap4;
                str2 = "data";
                arrayList3 = new ArrayList();
                while (i10 + 9 <= bArr2.length) {
                    int i136 = i10 + 1;
                    int i137 = i136 + 1;
                    int i138 = (bArr2[i10] & 255) + ((bArr2[i136] & 255) << 8);
                    int i139 = i138 + ((bArr2[i137] & 255) << 16);
                    int i140 = i137 + 1 + 1;
                    int i141 = i140 + 1;
                    int i142 = bArr2[i140] & 255;
                    int i143 = i141 + 1;
                    int i144 = i143 + 1;
                    float parseFloat = Float.parseFloat((bArr2[i141] & 255) + "." + (bArr2[i143] & 255));
                    int i145 = i144 + 1;
                    int i146 = i145 + 1;
                    float parseFloat2 = Float.parseFloat((bArr2[i144] & 255) + "." + (bArr2[i145] & 255));
                    HashMap hashMap12 = new HashMap();
                    hashMap12.put("startTime", Long.valueOf((((i139 + ((bArr2[r0] & 255) << 24)) + 946684800) * 1000) - offset));
                    hashMap12.put("type", Integer.valueOf(i142));
                    hashMap12.put("tempValue", Float.valueOf(parseFloat));
                    hashMap12.put("humidValue", Float.valueOf(parseFloat2));
                    arrayList3.add(hashMap12);
                    i10 = i146;
                }
                i8 = Constants.DATATYPE.Health_HistoryTempAndHumidity;
                i3 = i8;
                arrayList = arrayList3;
                hashMap = hashMap2;
                str = str2;
                hashMap.put("dataType", Integer.valueOf(i3));
                hashMap.put(str, arrayList);
                return hashMap;
            case 30:
                hashMap2 = hashMap4;
                str2 = "data";
                arrayList3 = new ArrayList();
                while (i10 + 5 <= bArr2.length) {
                    int i147 = i10 + 1;
                    int i148 = i147 + 1;
                    int i149 = (bArr2[i10] & 255) + ((bArr2[i147] & 255) << 8);
                    int i150 = i149 + ((bArr2[i148] & 255) << 16);
                    int i151 = i148 + 1 + 1;
                    int i152 = i151 + 1;
                    int i153 = bArr2[i151] & 255;
                    int i154 = i152 + 1;
                    int i155 = i154 + 1;
                    float parseFloat3 = Float.parseFloat((bArr2[i152] & 255) + "." + (bArr2[i154] & 255));
                    HashMap hashMap13 = new HashMap();
                    hashMap13.put("startTime", Long.valueOf((((i150 + ((bArr2[r0] & 255) << 24)) + 946684800) * 1000) - offset));
                    hashMap13.put("type", Integer.valueOf(i153));
                    hashMap13.put("tempValue", Float.valueOf(parseFloat3));
                    arrayList3.add(hashMap13);
                    i10 = i155;
                }
                i8 = Constants.DATATYPE.Health_HistoryTemp;
                i3 = i8;
                arrayList = arrayList3;
                hashMap = hashMap2;
                str = str2;
                hashMap.put("dataType", Integer.valueOf(i3));
                hashMap.put(str, arrayList);
                return hashMap;
            case 32:
                hashMap2 = hashMap4;
                str2 = "data";
                arrayList3 = new ArrayList();
                while (i10 + 6 <= bArr2.length) {
                    int i156 = i10 + 1;
                    int i157 = i156 + 1;
                    int i158 = (bArr2[i10] & 255) + ((bArr2[i156] & 255) << 8);
                    int i159 = i158 + ((bArr2[i157] & 255) << 16);
                    int i160 = i157 + 1 + 1;
                    int i161 = i160 + 1;
                    int i162 = bArr2[i160] & 255;
                    int i163 = i161 + 1;
                    int i164 = i163 + 1;
                    int i165 = (bArr2[i161] & 255) + ((bArr2[i163] & 255) << 8);
                    HashMap hashMap14 = new HashMap();
                    hashMap14.put("startTime", Long.valueOf((((i159 + ((bArr2[r0] & 255) << 24)) + 946684800) * 1000) - offset));
                    hashMap14.put("type", Integer.valueOf(i162));
                    hashMap14.put("value", Integer.valueOf(i165));
                    arrayList3.add(hashMap14);
                    i10 = i164;
                }
                i8 = Constants.DATATYPE.Health_HistoryAmbientLight;
                i3 = i8;
                arrayList = arrayList3;
                hashMap = hashMap2;
                str = str2;
                hashMap.put("dataType", Integer.valueOf(i3));
                hashMap.put(str, arrayList);
                return hashMap;
            case 41:
                hashMap2 = hashMap4;
                str2 = "data";
                arrayList3 = new ArrayList();
                while (i10 + 5 <= bArr.length) {
                    int i166 = i10 + 1;
                    int i167 = i166 + 1;
                    int i168 = (bArr[i10] & 255) + ((bArr[i166] & 255) << 8);
                    int i169 = i168 + ((bArr[i167] & 255) << 16);
                    int i170 = i167 + 1 + 1;
                    i10 = i170 + 1;
                    int i171 = bArr[i170] & 255;
                    HashMap hashMap15 = new HashMap();
                    hashMap15.put("startTime", Long.valueOf((((i169 + ((bArr[r0] & 255) << 24)) + 946684800) * 1000) - offset));
                    hashMap15.put(ServerProtocol.DIALOG_PARAM_STATE, Integer.valueOf(i171));
                    arrayList3.add(hashMap15);
                }
                i8 = Constants.DATATYPE.Health_HistoryFall;
                i3 = i8;
                arrayList = arrayList3;
                hashMap = hashMap2;
                str = str2;
                hashMap.put("dataType", Integer.valueOf(i3));
                hashMap.put(str, arrayList);
                return hashMap;
            case 43:
                hashMap2 = hashMap4;
                str2 = "data";
                arrayList4 = new ArrayList();
                while (i10 + 30 <= bArr.length) {
                    int i172 = i10 + 1;
                    int i173 = i172 + 1;
                    int i174 = (bArr[i10] & 255) + ((bArr[i172] & 255) << 8);
                    int i175 = i174 + ((bArr[i173] & 255) << 16);
                    int i176 = i173 + 1 + 1;
                    long j15 = (i175 + ((bArr[r1] & 255) << 24) + 946684800) * 1000;
                    int i177 = i176 + 1;
                    int i178 = bArr[i176] & 255;
                    int i179 = i177 + 1;
                    int i180 = i178 + ((bArr[i177] & 255) << 8);
                    int i181 = i179 + 1;
                    int i182 = i180 + ((bArr[i179] & 255) << 16);
                    int i183 = i181 + 1;
                    ArrayList arrayList12 = arrayList4;
                    long j16 = i182 + ((bArr[i181] & 255) << 24);
                    int i184 = i183 + 1;
                    int i185 = bArr[i183] & 255;
                    int i186 = i184 + 1;
                    int i187 = bArr[i184] & 255;
                    int i188 = i186 + 1;
                    int i189 = bArr[i186] & 255;
                    int i190 = i188 + 1;
                    int i191 = bArr[i188] & 255;
                    int i192 = i190 + 1;
                    int i193 = bArr[i190] & 255;
                    int i194 = i192 + 1;
                    String str6 = str3;
                    int i195 = bArr[i192] & 255;
                    int i196 = i194 + 1;
                    String str7 = str4;
                    int i197 = bArr[i194] & 255;
                    int i198 = i196 + 1;
                    int i199 = bArr[i196] & 255;
                    int i200 = i198 + 1;
                    int i201 = bArr[i198] & 255;
                    int i202 = i200 + 1;
                    int i203 = bArr[i200] & 255;
                    int i204 = i202 + 1;
                    int i205 = bArr[i202] & 255;
                    int i206 = i204 + 1;
                    int i207 = bArr[i204] & 255;
                    int i208 = i206 + 1;
                    int i209 = i207 + ((bArr[i206] & 255) << 8);
                    int i210 = i208 + 1;
                    int i211 = bArr[i208] & 255;
                    int i212 = i210 + 1;
                    int i213 = i212 + 1;
                    int i214 = (bArr[i210] & 255) + ((bArr[i212] & 255) << 8);
                    int i215 = bArr[i213] & 255;
                    HashMap hashMap16 = new HashMap();
                    hashMap16.put("startTime", Long.valueOf(j15 - offset));
                    hashMap16.put("stepValue", Long.valueOf(j16));
                    hashMap16.put("heartValue", Integer.valueOf(i185));
                    hashMap16.put("DBPValue", Integer.valueOf(i189));
                    hashMap16.put("SBPValue", Integer.valueOf(i187));
                    hashMap16.put("OOValue", Integer.valueOf(i191));
                    hashMap16.put("respiratoryRateValue", Integer.valueOf(i193));
                    hashMap16.put("hrvValue", Integer.valueOf(i195));
                    hashMap16.put("cvrrValue", Integer.valueOf(i197));
                    hashMap16.put("tempIntValue", Integer.valueOf(i199));
                    hashMap16.put("tempFloatValue", Integer.valueOf(i201));
                    hashMap16.put("humidIntValue", Integer.valueOf(i203));
                    hashMap16.put("humidFloatValue", Integer.valueOf(i205));
                    hashMap16.put("ambientLightValue", Integer.valueOf(i209));
                    hashMap16.put("isSprotMode", Integer.valueOf(i211));
                    hashMap16.put(str7, Integer.valueOf(i214));
                    hashMap16.put(str6, Integer.valueOf(i215));
                    arrayList4 = arrayList12;
                    arrayList4.add(hashMap16);
                    str4 = str7;
                    str3 = str6;
                    i10 = i213 + 1 + 4;
                }
                i3 = Constants.DATATYPE.Health_HistoryHealthMonitoring;
                arrayList = arrayList4;
                hashMap = hashMap2;
                str = str2;
                hashMap.put("dataType", Integer.valueOf(i3));
                hashMap.put(str, arrayList);
                return hashMap;
            case 45:
                hashMap2 = hashMap4;
                str2 = "data";
                ArrayList arrayList13 = new ArrayList();
                while (i10 + 26 <= bArr.length) {
                    int i216 = i10 + 1;
                    int i217 = bArr[i10] & 255;
                    int i218 = i216 + 1;
                    int i219 = i217 + ((bArr[i216] & 255) << 8);
                    int i220 = i218 + 1;
                    int i221 = i219 + ((bArr[i218] & 255) << 16);
                    int i222 = i220 + 1;
                    long j17 = i221 + ((bArr[i220] & 255) << 24);
                    int i223 = i222 + 1;
                    int i224 = bArr[i222] & 255;
                    int i225 = i223 + 1;
                    int i226 = i224 + ((bArr[i223] & 255) << 8);
                    int i227 = i226 + ((bArr[i225] & 255) << 16);
                    int i228 = i225 + 1 + 1;
                    long j18 = (i227 + ((bArr[r0] & 255) << 24) + 946684800) * 1000;
                    int i229 = i228 + 1;
                    int i230 = bArr[i228] & 255;
                    int i231 = i229 + 1;
                    int i232 = i230 + ((bArr[i229] & 255) << 8);
                    int i233 = i231 + 1;
                    int i234 = i232 + ((bArr[i231] & 255) << 16);
                    int i235 = i233 + 1;
                    int i236 = i234 + ((bArr[i233] & 255) << 24);
                    int i237 = i235 + 1;
                    int i238 = i237 + 1;
                    int i239 = (bArr[i235] & 255) + ((bArr[i237] & 255) << 8);
                    int i240 = i238 + 1;
                    int i241 = i240 + 1;
                    int i242 = (bArr[i238] & 255) + ((bArr[i240] & 255) << 8);
                    int i243 = i241 + 1;
                    int i244 = bArr[i241] & 255;
                    int i245 = i243 + 1;
                    int i246 = bArr[i243] & 255;
                    int i247 = i245 + 1;
                    int i248 = bArr[i245] & 255;
                    int i249 = i247 + 1;
                    int i250 = i249 + 1;
                    int i251 = (bArr[i247] & 255) + ((bArr[i249] & 255) << 8);
                    int i252 = i250 + 1;
                    ArrayList arrayList14 = arrayList13;
                    int i253 = i252 + 1;
                    long j19 = i251 + ((bArr[i250] & 255) << 16) + ((bArr[i252] & 255) << 24);
                    int i254 = i253 + 1;
                    int i255 = bArr[i253] & 255;
                    int i256 = bArr[i254] & 255;
                    HashMap hashMap17 = new HashMap();
                    long j20 = offset;
                    hashMap17.put("startTime", Long.valueOf(((j17 + 946684800) * 1000) - j20));
                    hashMap17.put("endTime", Long.valueOf(j18 - j20));
                    hashMap17.put("sportSteps", Integer.valueOf(i236));
                    hashMap17.put("sportDistances", Integer.valueOf(i239));
                    hashMap17.put("sportCalories", Integer.valueOf(i242));
                    hashMap17.put("sportMode", Integer.valueOf(i244));
                    hashMap17.put("startMethod", Integer.valueOf(i246));
                    hashMap17.put("sportHeartRate", Integer.valueOf(i248));
                    hashMap17.put("sportTime", Long.valueOf(j19));
                    hashMap17.put("minHeartRate", Integer.valueOf(i255));
                    hashMap17.put("maxHeartRate", Integer.valueOf(i256));
                    arrayList14.add(hashMap17);
                    arrayList13 = arrayList14;
                    i10 = i254 + 1 + 1;
                }
                arrayList4 = arrayList13;
                i3 = Constants.DATATYPE.Health_HistorySportMode;
                arrayList = arrayList4;
                hashMap = hashMap2;
                str = str2;
                hashMap.put("dataType", Integer.valueOf(i3));
                hashMap.put(str, arrayList);
                return hashMap;
            case 47:
                hashMap3 = hashMap4;
                String str8 = "data";
                ArrayList arrayList15 = new ArrayList();
                while (i10 + 44 <= bArr2.length) {
                    int i257 = i10 + 1;
                    int i258 = i257 + 1;
                    int i259 = (bArr2[i10] & 255) + ((bArr2[i257] & 255) << 8);
                    int i260 = i259 + ((bArr2[i258] & 255) << 16);
                    int i261 = i258 + 1 + 1;
                    long j21 = (i260 + ((bArr2[r1] & 255) << 24) + 946684800) * 1000;
                    int i262 = i261 + 1;
                    int i263 = bArr2[i261] & 255;
                    int i264 = i262 + 1;
                    int i265 = bArr2[i262] & 255;
                    int i266 = i264 + 1;
                    int i267 = bArr2[i264] & 255;
                    int i268 = i266 + 1;
                    int i269 = bArr2[i266] & 255;
                    int i270 = i268 + 1;
                    int i271 = i270 + 1;
                    int i272 = (bArr2[i268] & 255) + ((bArr2[i270] & 255) << 8);
                    int i273 = i271 + 1;
                    int i274 = bArr2[i271] & 255;
                    int i275 = i273 + 1;
                    int i276 = bArr2[i273] & 255;
                    int i277 = i275 + 1;
                    int i278 = bArr2[i275] & 255;
                    int i279 = i277 + 1;
                    int i280 = bArr2[i277] & 255;
                    int i281 = i279 + 1;
                    String str9 = str8;
                    int i282 = bArr2[i279] & 255;
                    int i283 = i281 + 1;
                    ArrayList arrayList16 = arrayList15;
                    int i284 = bArr2[i281] & 255;
                    int i285 = i283 + 1;
                    int i286 = bArr2[i283] & 255;
                    int i287 = i285 + 1;
                    int i288 = bArr2[i285] & 255;
                    int i289 = i287 + 1;
                    int i290 = bArr2[i287] & 255;
                    int i291 = i289 + 1;
                    int i292 = bArr2[i289] & 255;
                    int i293 = i291 + 1;
                    int i294 = bArr2[i291] & 255;
                    int i295 = bArr2[i293] & 255;
                    HashMap hashMap18 = new HashMap();
                    hashMap18.put("time", Long.valueOf(j21 - offset));
                    hashMap18.put("bloodSugarModel", Integer.valueOf(i263));
                    hashMap18.put("bloodSugarInteger", Integer.valueOf(i265));
                    hashMap18.put("bloodSugarFloat", Integer.valueOf(i267));
                    hashMap18.put("uricAcidModel", Integer.valueOf(i269));
                    hashMap18.put("uricAcid", Integer.valueOf(i272));
                    hashMap18.put("bloodKetoneModel", Integer.valueOf(i274));
                    hashMap18.put("bloodKetoneInteger", Integer.valueOf(i276));
                    hashMap18.put("bloodKetoneFloat", Integer.valueOf(i278));
                    hashMap18.put("bloodFatModel", Integer.valueOf(i280));
                    hashMap18.put("cholesterolInteger", Integer.valueOf(i282));
                    hashMap18.put("cholesterolFloat", Integer.valueOf(i284));
                    hashMap18.put("highLipoproteinCholesterolInteger", Integer.valueOf(i286));
                    hashMap18.put("highLipoproteinCholesterolFloat", Integer.valueOf(i288));
                    hashMap18.put("lowLipoproteinCholesterolInteger", Integer.valueOf(i290));
                    hashMap18.put("lowLipoproteinCholesterolFloat", Integer.valueOf(i292));
                    hashMap18.put("triglycerideCholesterolInteger", Integer.valueOf(i294));
                    hashMap18.put("triglycerideCholesterolFloat", Integer.valueOf(i295));
                    arrayList16.add(hashMap18);
                    bArr2 = bArr;
                    arrayList15 = arrayList16;
                    i10 = i293 + 1 + 22;
                    str8 = str9;
                }
                str2 = str8;
                arrayList5 = arrayList15;
                i9 = Constants.DATATYPE.Health_HistoryComprehensiveMeasureData;
                arrayList = arrayList5;
                hashMap = hashMap3;
                i3 = i9;
                str = str2;
                hashMap.put("dataType", Integer.valueOf(i3));
                hashMap.put(str, arrayList);
                return hashMap;
            case 49:
                ArrayList arrayList17 = new ArrayList();
                while (i10 + 44 <= bArr2.length) {
                    int i296 = i10 + 1;
                    int i297 = bArr2[i10] & 255;
                    int i298 = i296 + 1;
                    int i299 = i297 + ((bArr2[i296] & 255) << 8);
                    int i300 = i299 + ((bArr2[i298] & 255) << 16);
                    int i301 = i298 + 1 + 1;
                    int i302 = i301 + 1;
                    int i303 = bArr2[i301] & 255;
                    HashMap hashMap19 = new HashMap();
                    hashMap19.put("time", Long.valueOf((((i300 + ((bArr2[r1] & 255) << 24)) + 946684800) * 1000) - offset));
                    hashMap19.put("data", Integer.valueOf(i303));
                    i10 = i302 + 3;
                }
                i3 = 1329;
                str = "data";
                arrayList = arrayList17;
                hashMap = hashMap4;
                hashMap.put("dataType", Integer.valueOf(i3));
                hashMap.put(str, arrayList);
                return hashMap;
            case 51:
                ArrayList arrayList18 = new ArrayList();
                while (i10 + 28 <= bArr2.length) {
                    int i304 = i10 + 1;
                    int i305 = i304 + 1;
                    int i306 = (bArr2[i10] & 255) + ((bArr2[i304] & 255) << 8);
                    int i307 = i306 + ((bArr2[i305] & 255) << 16);
                    int i308 = i305 + 1 + 1;
                    long j22 = (((i307 + ((bArr2[r5] & 255) << 24)) + j3) * j2) - offset;
                    int i309 = i308 + 1;
                    int i310 = bArr2[i308] & 255;
                    int i311 = i309 + 1;
                    int i312 = bArr2[i309] & 255;
                    int i313 = i311 + 1;
                    int i314 = bArr2[i311] & 255;
                    int i315 = i313 + 1;
                    int i316 = bArr2[i313] & 255;
                    int i317 = i315 + 1;
                    int i318 = bArr2[i315] & 255;
                    int i319 = i317 + 1;
                    int i320 = bArr2[i317] & 255;
                    int i321 = i319 + 1;
                    int i322 = bArr2[i319] & 255;
                    int i323 = i321 + 1;
                    int i324 = bArr2[i321] & 255;
                    int i325 = i323 + 1;
                    HashMap hashMap20 = hashMap4;
                    int i326 = bArr2[i323] & 255;
                    int i327 = i325 + 1;
                    String str10 = str5;
                    int i328 = bArr2[i325] & 255;
                    int i329 = i327 + 1;
                    int i330 = offset;
                    int i331 = bArr2[i327] & 255;
                    int i332 = i329 + 1;
                    ArrayList arrayList19 = arrayList18;
                    int i333 = i331 + ((bArr2[i329] & 255) << 8);
                    int i334 = bArr2[i332] & 255;
                    HashMap hashMap21 = new HashMap();
                    hashMap21.put("time", Long.valueOf(j22));
                    hashMap21.put("loadIndexInteger", Integer.valueOf(i310));
                    hashMap21.put("loadIndexFloat", Integer.valueOf(i312));
                    hashMap21.put("hrvInteger", Integer.valueOf(i314));
                    hashMap21.put("hrvFloat", Integer.valueOf(i316));
                    hashMap21.put("pressureInteger", Integer.valueOf(i318));
                    hashMap21.put("pressureFloat", Integer.valueOf(i320));
                    hashMap21.put("bodyInteger", Integer.valueOf(i322));
                    hashMap21.put("bodyFloat", Integer.valueOf(i324));
                    hashMap21.put("sympatheticInteger", Integer.valueOf(i326));
                    hashMap21.put("sympatheticFloat", Integer.valueOf(i328));
                    hashMap21.put("sdn", Integer.valueOf(i333));
                    hashMap21.put("maximalOxygenIntake", Integer.valueOf(i334));
                    arrayList19.add(hashMap21);
                    arrayList18 = arrayList19;
                    i10 = i332 + 1 + 9 + 2;
                    hashMap4 = hashMap20;
                    str5 = str10;
                    offset = i330;
                    j2 = 1000;
                    j3 = 946684800;
                }
                hashMap3 = hashMap4;
                arrayList5 = arrayList18;
                str2 = str5;
                i9 = Constants.DATATYPE.Health_History_Body_Data;
                arrayList = arrayList5;
                hashMap = hashMap3;
                i3 = i9;
                str = str2;
                hashMap.put("dataType", Integer.valueOf(i3));
                hashMap.put(str, arrayList);
                return hashMap;
            default:
                return hashMap4;
        }
    }

    public static HashMap unpackHomeTheme(byte[] bArr) {
        int i2;
        HashMap hashMap = new HashMap();
        int i3 = 0;
        hashMap.put("code", 0);
        if (bArr.length > 1) {
            int i4 = bArr[0] & 255;
            i3 = bArr[1] & 255;
            i2 = i4;
        } else {
            i2 = 0;
        }
        hashMap.put("themeTotal", Integer.valueOf(i2));
        hashMap.put("themeCurrentIndex", Integer.valueOf(i3));
        hashMap.put("dataType", 521);
        return hashMap;
    }

    public static HashMap unpackInsuranceNews(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr != null && bArr.length >= 1) {
            hashMap.put("result", Integer.valueOf(bArr[0] & 255));
            if (bArr.length >= 2) {
                hashMap.put("tpeResult", Integer.valueOf(bArr[1] & 255));
            }
        }
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.AppInsuranceNews));
        return hashMap;
    }

    public static HashMap unpackMulPhotoelectricWaveform(byte[] bArr) {
        HashMap hashMap = new HashMap();
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        ArrayList arrayList3 = new ArrayList();
        ArrayList arrayList4 = new ArrayList();
        if (bArr != null) {
            int i2 = bArr[0] & 255;
            hashMap.put("sampleType", Integer.valueOf(i2));
            int i3 = 1;
            if (i2 == 0) {
                while (i3 < bArr.length) {
                    int i4 = i3 + 1;
                    int i5 = i4 + 1;
                    int i6 = (bArr[i3] & 255) + ((bArr[i4] & 255) << 8);
                    int i7 = i5 + 1;
                    int i8 = i6 + ((bArr[i5] & 255) << 16);
                    int i9 = i7 + 1;
                    int i10 = i8 + ((bArr[i7] & 255) << 24);
                    int i11 = i9 + 1;
                    int i12 = i11 + 1;
                    int i13 = (bArr[i9] & 255) + ((bArr[i11] & 255) << 8);
                    int i14 = i12 + 1;
                    int i15 = i13 + ((bArr[i12] & 255) << 16);
                    int i16 = i14 + 1;
                    int i17 = i15 + ((bArr[i14] & 255) << 24);
                    int i18 = i16 + 1;
                    int i19 = i18 + 1;
                    int i20 = (bArr[i16] & 255) + ((bArr[i18] & 255) << 8);
                    int i21 = i19 + 1;
                    int i22 = i20 + ((bArr[i19] & 255) << 16);
                    int i23 = i22 + ((bArr[i21] & 255) << 24);
                    arrayList.add(Integer.valueOf(i10));
                    arrayList2.add(Integer.valueOf(i10));
                    arrayList.add(Integer.valueOf(i17));
                    arrayList3.add(Integer.valueOf(i17));
                    arrayList.add(Integer.valueOf(i23));
                    arrayList4.add(Integer.valueOf(i23));
                    i3 = i21 + 1;
                }
            } else if (i2 == 1) {
                while (i3 < bArr.length) {
                    int i24 = i3 + 1;
                    int i25 = i24 + 1;
                    int i26 = ((bArr[i3] & 255) << 24) + ((bArr[i24] & 255) << 16);
                    int i27 = i25 + 1;
                    int i28 = i26 + ((bArr[i25] & 255) << 8);
                    int i29 = i27 + 1;
                    int i30 = i28 + (bArr[i27] & 255);
                    int i31 = i29 + 1;
                    int i32 = i31 + 1;
                    int i33 = ((bArr[i29] & 255) << 24) + ((bArr[i31] & 255) << 16);
                    int i34 = i32 + 1;
                    int i35 = i33 + ((bArr[i32] & 255) << 8);
                    int i36 = i35 + (bArr[i34] & 255);
                    arrayList.add(Integer.valueOf(i30));
                    arrayList2.add(Integer.valueOf(i30));
                    arrayList.add(Integer.valueOf(i36));
                    arrayList3.add(Integer.valueOf(i36));
                    i3 = i34 + 1;
                }
            } else if (i2 == 2) {
                while (i3 < bArr.length) {
                    int i37 = i3 + 1;
                    int i38 = i37 + 1;
                    int i39 = ((bArr[i3] & 255) << 24) + ((bArr[i37] & 255) << 16);
                    int i40 = i38 + 1;
                    int i41 = i39 + ((bArr[i38] & 255) << 8);
                    int i42 = i40 + 1;
                    int i43 = i41 + (bArr[i40] & 255);
                    int i44 = i42 + 1;
                    int i45 = i44 + 1;
                    int i46 = ((bArr[i42] & 255) << 24) + ((bArr[i44] & 255) << 16);
                    int i47 = i45 + 1;
                    int i48 = i46 + ((bArr[i45] & 255) << 8);
                    int i49 = i48 + (bArr[i47] & 255);
                    arrayList.add(Integer.valueOf(i43));
                    arrayList3.add(Integer.valueOf(i43));
                    arrayList.add(Integer.valueOf(i49));
                    arrayList4.add(Integer.valueOf(i49));
                    i3 = i47 + 1;
                }
            }
        }
        hashMap.put("green", arrayList2);
        hashMap.put("ir", arrayList3);
        hashMap.put("red", arrayList4);
        hashMap.put("data", arrayList);
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Real_UploadMulPhotoelectricWaveform));
        return hashMap;
    }

    public static HashMap unpackOTAData(byte[] bArr) {
        int i2 = bArr[0] & 255;
        int i3 = bArr[1] & 255;
        HashMap hashMap = new HashMap();
        hashMap.put(ServerProtocol.DIALOG_PARAM_STATE, Integer.valueOf(i2));
        hashMap.put("success", Integer.valueOf(i3));
        hashMap.put("code", 0);
        hashMap.put("dataType", 2560);
        return hashMap;
    }

    public static HashMap unpackParseData(byte[] bArr, int i2) {
        byte b2;
        HashMap hashMap = new HashMap();
        if (bArr != null && bArr.length >= 1) {
            if (bArr.length > 1) {
                switch (i2) {
                    case Constants.DATATYPE.DevicePPIData /* 1042 */:
                        hashMap.put("ppi", Long.valueOf((bArr[0] & 255) + ((bArr[1] & 255) << 8) + ((bArr[2] & 255) << 16) + ((bArr[3] & 255) << 24)));
                        break;
                    case Constants.DATATYPE.DeviceMeasurStatusAndResults /* 1043 */:
                        if (bArr.length >= 24) {
                            int i3 = bArr[0] & 255;
                            int i4 = bArr[1] & 255;
                            hashMap.put("type", Integer.valueOf(i3));
                            hashMap.put(ServerProtocol.DIALOG_PARAM_STATE, Integer.valueOf(i4));
                            switch (i3) {
                                case 0:
                                    hashMap.put("heartRate", Integer.valueOf(bArr[2] & 255));
                                    break;
                                case 1:
                                    hashMap.put("SBP", Integer.valueOf(bArr[2] & 255));
                                    hashMap.put("DBP", Integer.valueOf(bArr[3] & 255));
                                    break;
                                case 2:
                                    hashMap.put("bloodOxygen", Integer.valueOf(bArr[2] & 255));
                                    break;
                                case 3:
                                    hashMap.put("respiratoryRate", Integer.valueOf(bArr[2] & 255));
                                    break;
                                case 4:
                                    hashMap.put("tempInteger", Integer.valueOf(bArr[2] & 255));
                                    hashMap.put("tempFloat", Integer.valueOf(bArr[3] & 255));
                                    break;
                                case 5:
                                    hashMap.put("bloodSugarInteger", Integer.valueOf(bArr[2] & 255));
                                    hashMap.put("bloodSugarFloat", Integer.valueOf(bArr[3] & 255));
                                    break;
                                case 6:
                                    hashMap.put("uricAcid", Integer.valueOf((bArr[2] & 255) + ((bArr[3] & 255) << 8)));
                                    break;
                                case 7:
                                    hashMap.put("bloodKetoneInteger", Integer.valueOf(bArr[2] & 255));
                                    hashMap.put("bloodKetoneFloat", Integer.valueOf(bArr[3] & 255));
                                    break;
                            }
                        }
                        break;
                    case 1044:
                    default:
                        hashMap.put("datas", bArr);
                        break;
                    case Constants.DATATYPE.DeviceRequestDynamicCode /* 1045 */:
                        b2 = bArr[0];
                        break;
                    case Constants.DATATYPE.DeviceSedentaryReminder /* 1046 */:
                        hashMap.put("alarmType", Integer.valueOf(bArr[0] & 255));
                        break;
                    case Constants.DATATYPE.DeviceReportAlarm /* 1047 */:
                        hashMap.put("alarmType", Integer.valueOf(bArr[0] & 255));
                        break;
                }
            } else {
                b2 = bArr[0];
            }
            hashMap.put("data", Integer.valueOf(b2 & 255));
        }
        hashMap.put("dataType", Integer.valueOf(i2));
        return hashMap;
    }

    public static HashMap unpackRealAmbientlightData(byte[] bArr) {
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Real_UploadAmbientlight));
        return hashMap;
    }

    public static HashMap unpackRealBloodData(byte[] bArr) {
        int i2 = 3;
        if (bArr.length < 3) {
            return null;
        }
        int i3 = bArr[0] & 255;
        int i4 = bArr[1] & 255;
        int i5 = bArr[2] & 255;
        YCBTLog.e("实时血压 DBP " + i4 + " SBP " + i3 + " Heart " + i5);
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", 1539);
        hashMap.put("heartValue", Integer.valueOf(i5));
        hashMap.put("bloodDBP", Integer.valueOf(i4));
        hashMap.put("bloodSBP", Integer.valueOf(i3));
        if (bArr.length > 3) {
            hashMap.put("hrv", Integer.valueOf(bArr[3] & 255));
            i2 = 4;
        }
        if (bArr.length > 4) {
            hashMap.put("bloodOxygen", Integer.valueOf(bArr[i2] & 255));
            i2++;
        }
        if (bArr.length > 6) {
            int i6 = i2 + 1;
            int i7 = bArr[i2] & 255;
            int i8 = bArr[i6] & 255;
            hashMap.put("tempInteger", Integer.valueOf(i7));
            hashMap.put("tempFloat", Integer.valueOf(i8));
        }
        return hashMap;
    }

    public static HashMap unpackRealBloodOxygenData(byte[] bArr) {
        int i2 = bArr[0] & 255;
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", 1538);
        hashMap.put("bloodOxygenValue", Integer.valueOf(i2));
        return hashMap;
    }

    public static HashMap unpackRealComprehensiveData(byte[] bArr) {
        if (bArr.length < 20) {
            return null;
        }
        int i2 = (bArr[0] & 255) + ((bArr[1] & 255) << 8) + ((bArr[2] & 255) << 16);
        int i3 = (bArr[3] & 255) + ((bArr[4] & 255) << 8);
        int i4 = (bArr[5] & 255) + ((bArr[6] & 255) << 8);
        int i5 = bArr[7] & 255;
        int i6 = bArr[8] & 255;
        int i7 = bArr[9] & 255;
        int i8 = bArr[10] & 255;
        int i9 = bArr[11] & 255;
        int i10 = bArr[12] & 255;
        int i11 = bArr[13] & 255;
        int i12 = bArr[14] & 255;
        int i13 = bArr[15] & 255;
        int i14 = (bArr[16] & 255) + ((bArr[17] & 255) << 8) + ((bArr[18] & 255) << 16) + ((bArr[19] & 255) << 24);
        int i15 = bArr[20] & 255;
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Real_UploadComprehensive));
        hashMap.put("step", Integer.valueOf(i2));
        hashMap.put("dis", Integer.valueOf(i3));
        hashMap.put("kcal", Integer.valueOf(i4));
        hashMap.put("heartRate", Integer.valueOf(i5));
        hashMap.put("SBP", Integer.valueOf(i6));
        hashMap.put("DBP", Integer.valueOf(i7));
        hashMap.put("bloodOxygen", Integer.valueOf(i8));
        hashMap.put("respirationRate", Integer.valueOf(i9));
        hashMap.put("tempInteger", Integer.valueOf(i10));
        hashMap.put("tempFloat", Integer.valueOf(i11));
        hashMap.put("wearingState", Integer.valueOf(i12));
        hashMap.put("electricity", Integer.valueOf(i13));
        hashMap.put("ppi", Integer.valueOf(i14));
        hashMap.put("bloodSugar", Integer.valueOf(i15));
        return hashMap;
    }

    public static HashMap unpackRealECGData(byte[] bArr) {
        HashMap<String, List<Integer>> ecgRealWaveFilteringMap = AITools.getInstance().ecgRealWaveFilteringMap(bArr);
        ecgRealWaveFilteringMap.put("code", 0);
        ecgRealWaveFilteringMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Real_UploadECG));
        return ecgRealWaveFilteringMap;
    }

    public static HashMap unpackRealGsensorData(byte[] bArr) {
        int i2 = bArr[0] & 255;
        int i3 = bArr[1] & 255;
        int i4 = bArr[2] & 255;
        int i5 = bArr[3] & 255;
        ArrayList arrayList = new ArrayList();
        int i6 = 4;
        int i7 = 0;
        while (i7 < i5) {
            try {
                GsensorBean gsensorBean = new GsensorBean();
                int i8 = i6 + 1;
                int i9 = i8 + 1;
                gsensorBean.x = Short.valueOf((short) ((bArr[i6] & 255) + ((bArr[i8] & 255) << 8)));
                int i10 = i9 + 1;
                int i11 = bArr[i9] & 255;
                int i12 = i10 + 1;
                gsensorBean.y = Short.valueOf((short) (i11 + ((bArr[i10] & 255) << 8)));
                int i13 = i12 + 1;
                int i14 = bArr[i12] & 255;
                int i15 = i13 + 1;
                gsensorBean.z = Short.valueOf((short) (i14 + ((bArr[i13] & 255) << 8)));
                arrayList.add(gsensorBean);
                i7++;
                i6 = i15;
            } catch (Exception e2) {
                YCBTLog.e("gsensor 数据解析异常:" + e2.getMessage());
                e2.printStackTrace();
            }
        }
        YCBTLog.e("gsensor 操作码" + i2 + " 姿态 " + i3 + " 长度 " + i5);
        YCBTLog.e(new Gson().toJson(arrayList));
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Gsensor));
        hashMap.put("operateCode", Integer.valueOf(i2));
        hashMap.put("posture", Integer.valueOf(i3));
        hashMap.put("dataLength", Integer.valueOf(i4));
        hashMap.put("gsensorBeanList", arrayList);
        return hashMap;
    }

    public static HashMap unpackRealHeartData(byte[] bArr) {
        int i2 = bArr[0] & 255;
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", 1537);
        hashMap.put("heartValue", Integer.valueOf(i2));
        return hashMap;
    }

    public static HashMap unpackRealPPGData(byte[] bArr) {
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Real_UploadPPG));
        hashMap.put("data", bArr);
        return hashMap;
    }

    public static HashMap unpackRealRespiratoryRateData(byte[] bArr) {
        int i2 = bArr[0] & 255;
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Real_UploadRespiratoryRate));
        hashMap.put("respiratoryRateValue", Integer.valueOf(i2));
        return hashMap;
    }

    public static HashMap unpackRealSensorData(byte[] bArr) {
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Real_UploadSensor));
        return hashMap;
    }

    public static HashMap unpackRealSportData(byte[] bArr) {
        int i2 = (bArr[0] & 255) + ((bArr[1] & 255) << 8);
        int i3 = (bArr[2] & 255) + ((bArr[3] & 255) << 8);
        int i4 = (bArr[4] & 255) + ((bArr[5] & 255) << 8);
        YCBTLog.e("实时步数 " + i2 + " Dis " + i3 + " Cal " + i4);
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Real_UploadSport));
        hashMap.put("sportStep", Integer.valueOf(i2));
        hashMap.put("sportCalorie", Integer.valueOf(i4));
        hashMap.put("sportDistance", Integer.valueOf(i3));
        return hashMap;
    }

    public static HashMap unpackRealUploadRunData(byte[] bArr) {
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Real_UploadRun));
        return hashMap;
    }

    public static HashMap unpackUIFileBreakInfo(byte[] bArr) {
        HashMap hashMap = new HashMap();
        if (bArr.length > 8) {
            int i2 = (bArr[0] & 255) + ((bArr[1] & 255) << 8) + ((bArr[2] & 255) << 16) + ((bArr[3] & 255) << 24);
            int i3 = (bArr[4] & 255) + ((bArr[5] & 255) << 8) + ((bArr[6] & 255) << 16) + ((bArr[7] & 255) << 24);
            int i4 = (bArr[8] & 255) + ((bArr[9] & 255) << 8);
            YCBTLog.e("总长度 " + i2 + " 已升级偏移量 " + i3 + " 检验码 " + i4);
            hashMap.put("code", 0);
            hashMap.put("dataType", 32256);
            hashMap.put("uiFileTotalLen", Integer.valueOf(i2));
            hashMap.put("uiFileOffset", Integer.valueOf(i3));
            hashMap.put("uiFileCheckSum", Integer.valueOf(i4));
        } else {
            hashMap.put("code", 1);
        }
        return hashMap;
    }

    public static HashMap<String, Object> unpackWit(byte[] bArr) {
        HashMap<String, Object> hashMap = new HashMap<>();
        int i2 = bArr[0] & 255;
        hashMap.put("code", Integer.valueOf((bArr[1] & 255) << 8));
        hashMap.put(ServerProtocol.DIALOG_PARAM_STATE, Integer.valueOf(i2));
        return hashMap;
    }
}
