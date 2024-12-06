use serde::{Deserialize, Serialize, Serializer};

pub mod cfca;
pub mod ep;
pub mod ca_reader;

/// 签章信息枚举
#[derive(Serialize, Deserialize, Debug)]
pub enum EnQianZhangInfo {
    /// 字符串信息
    QianZhangStr(String),
    /// json数组
    QianZhangArr(serde_json::Value),
}
impl Default for EnQianZhangInfo {
    fn default() -> Self {
        Self::QianZhangStr(String::from(""))
    }
}
/// caobj结构体对象，用于转json
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CaObj {
    /// 设备介质号
    pub device_num: String,
    /// 签名证书base64
    pub sign_cert: String,
    /// 加密证书base64
    pub enc_cert: String,
    /// 签名证书序列号
    pub sign_cert_s_n: String,
    /// 加密证书序列号，其实是使用者密钥标识符
    pub enc_cert_s_n: String,
    /// 有效期截止时间
    pub yxq: String,
    /// 颁发机构
    pub bfjg: String,
    /// 使用单位名称
    pub orgname: String,
    /// 互联互通驱动标识
    pub by_union: bool,
    /// 签章信息
    #[serde(serialize_with = "qianzhanginfo_serializer")]
    pub qianzhanginfo: EnQianZhangInfo,
}
impl jyframe::JsonOut for CaObj {
}

fn qianzhanginfo_serializer<S>(value: &EnQianZhangInfo, serializer: S) -> Result<S::Ok, S::Error> 
where 
    S: Serializer
{
    match value {
        EnQianZhangInfo::QianZhangStr(s) => s.serialize(serializer),
        EnQianZhangInfo::QianZhangArr(arr) => arr.serialize(serializer),
    }
}