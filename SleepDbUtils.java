package com.yucheng.smarthealthpro.greendao.utils;

import android.content.Context;
import com.yucheng.smarthealthpro.greendao.SleepDbDao;
import com.yucheng.smarthealthpro.greendao.bean.SleepDb;
import com.yucheng.smarthealthpro.login.normal.util.UserInfoUtil;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.greenrobot.greendao.query.WhereCondition;

/* loaded from: classes2.dex */
public class SleepDbUtils {
    private static final String TAG = "SleepDbUtils";
    private static DaoManager daoManager;
    final int SLEEP_LIMIT_HIGH = 57600;

    public SleepDbUtils(Context context) {
        daoManager = DaoManager.getInstance();
    }

    public SleepDbUtils() {
        daoManager = DaoManager.getInstance();
    }

    public boolean insertMsgModel(SleepDb sleepDb) {
        return daoManager.getDaoSession().getSleepDbDao().insert(sleepDb) > 0;
    }

    public boolean insertMultMsgModel(final List<SleepDb> list) {
        try {
            daoManager.getDaoSession().runInTx(new Runnable() { // from class: com.yucheng.smarthealthpro.greendao.utils.SleepDbUtils.1
                @Override // java.lang.Runnable
                public void run() {
                    Iterator it2 = list.iterator();
                    while (it2.hasNext()) {
                        SleepDbUtils.daoManager.getDaoSession().insertOrReplace((SleepDb) it2.next());
                    }
                }
            });
            return true;
        } catch (Exception e2) {
            e2.printStackTrace();
            return false;
        }
    }

    public boolean updateMsgModel(SleepDb sleepDb) {
        try {
            daoManager.getDaoSession().update(sleepDb);
            return true;
        } catch (Exception e2) {
            e2.printStackTrace();
            return false;
        }
    }

    public boolean deleteMsgModel(SleepDb sleepDb) {
        try {
            daoManager.getDaoSession().delete(sleepDb);
            return true;
        } catch (Exception e2) {
            e2.printStackTrace();
            return false;
        }
    }

    public boolean deleteAll() {
        try {
            daoManager.getDaoSession().deleteAll(SleepDb.class);
            return true;
        } catch (Exception e2) {
            e2.printStackTrace();
            return false;
        }
    }

    public List<SleepDb> queryAllMsgModel() {
        try {
            return filter(daoManager.getDaoSession().queryBuilder(SleepDb.class).whereOr(SleepDbDao.Properties.UserId.eq(UserInfoUtil.getUserName()), SleepDbDao.Properties.UserId.isNull(), SleepDbDao.Properties.UserId.eq("")).orderAsc(SleepDbDao.Properties.StartTime).list());
        } catch (Exception e2) {
            e2.printStackTrace();
            return new ArrayList();
        }
    }

    public SleepDb queryMsgModelById(long j2) {
        return (SleepDb) daoManager.getDaoSession().load(SleepDb.class, Long.valueOf(j2));
    }

    public SleepDb queryMsgModelByQueryBuilder(long j2) {
        try {
            return (SleepDb) daoManager.getDaoSession().queryBuilder(SleepDb.class).where(SleepDbDao.Properties.Id.eq(Long.valueOf(j2)), new WhereCondition[0]).unique();
        } catch (Exception e2) {
            e2.printStackTrace();
            return null;
        }
    }

    public List<SleepDb> queryId(long j2) {
        try {
            return filter(daoManager.getDaoSession().queryBuilder(SleepDb.class).where(SleepDbDao.Properties.StartTime.eq(Long.valueOf(j2)), new WhereCondition[0]).list());
        } catch (Exception e2) {
            e2.printStackTrace();
            return null;
        }
    }

    public List<SleepDb> queryIdYearToDay(String str) {
        try {
            return filter(daoManager.getDaoSession().queryBuilder(SleepDb.class).where(SleepDbDao.Properties.TimeYearToDate.eq(str), new WhereCondition[0]).whereOr(SleepDbDao.Properties.UserId.eq(UserInfoUtil.getUserName()), SleepDbDao.Properties.UserId.isNull(), SleepDbDao.Properties.UserId.eq("")).orderAsc(SleepDbDao.Properties.StartTime).list());
        } catch (Exception e2) {
            e2.printStackTrace();
            return null;
        }
    }

    public List<SleepDb> filter(List<SleepDb> list) {
        int i2 = 0;
        while (i2 < list.size()) {
            SleepDb sleepDb = list.get(i2);
            if (sleepDb.getDeepSleepTotal() + sleepDb.getLightSleepTotal() + sleepDb.rapidEyeMovementTotal > 57600) {
                list.remove(i2);
                i2--;
            }
            i2++;
        }
        return list;
    }

    public List<SleepDb> queryGeTimeYearToDay(String str) {
        try {
            return daoManager.getDaoSession().queryBuilder(SleepDb.class).where(SleepDbDao.Properties.TimeYearToDate.ge(str), new WhereCondition[0]).whereOr(SleepDbDao.Properties.UserId.eq(UserInfoUtil.getUserName()), SleepDbDao.Properties.UserId.isNull(), SleepDbDao.Properties.UserId.eq("")).list();
        } catch (Exception e2) {
            e2.printStackTrace();
            return null;
        }
    }

    public List<SleepDb> queryEqTimeYearToDay(String str) {
        try {
            return filter(daoManager.getDaoSession().queryBuilder(SleepDb.class).where(SleepDbDao.Properties.TimeYearToDate.eq(str), new WhereCondition[0]).whereOr(SleepDbDao.Properties.UserId.eq(UserInfoUtil.getUserName()), SleepDbDao.Properties.UserId.isNull(), SleepDbDao.Properties.UserId.eq("")).orderDesc(SleepDbDao.Properties.StartTime).list());
        } catch (Exception e2) {
            e2.printStackTrace();
            return null;
        }
    }

    public boolean queryIdDelete(int i2) {
        SleepDb sleepDb = (SleepDb) daoManager.getDaoSession().queryBuilder(SleepDb.class).where(SleepDbDao.Properties.QueryID.eq(Integer.valueOf(i2)), new WhereCondition[0]).whereOr(SleepDbDao.Properties.UserId.eq(UserInfoUtil.getUserName()), SleepDbDao.Properties.UserId.isNull(), SleepDbDao.Properties.UserId.eq("")).unique();
        if (sleepDb != null) {
            try {
                daoManager.getDaoSession().delete(sleepDb);
                return true;
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        return false;
    }

    public List<SleepDb> queryGroupId(long j2) {
        try {
            return filter(daoManager.getDaoSession().queryBuilder(SleepDb.class).where(SleepDbDao.Properties.StartTime.ge(Long.valueOf(j2)), new WhereCondition[0]).where(SleepDbDao.Properties.EndTime.lt(Long.valueOf(j2)), new WhereCondition[0]).whereOr(SleepDbDao.Properties.UserId.eq(UserInfoUtil.getUserName()), SleepDbDao.Properties.UserId.isNull(), SleepDbDao.Properties.UserId.eq("")).orderDesc(SleepDbDao.Properties.StartTime).list());
        } catch (Exception e2) {
            e2.printStackTrace();
            return null;
        }
    }

    public List<SleepDb> queryByNotUpload() {
        try {
            return filter(daoManager.getDaoSession().queryBuilder(SleepDb.class).where(SleepDbDao.Properties.IsUpload.eq(false), new WhereCondition[0]).whereOr(SleepDbDao.Properties.UserId.eq(UserInfoUtil.getUserName()), SleepDbDao.Properties.UserId.isNull(), SleepDbDao.Properties.UserId.eq("")).orderDesc(SleepDbDao.Properties.StartTime).list());
        } catch (Exception e2) {
            e2.printStackTrace();
            return new ArrayList();
        }
    }
}
