use serde::{Serialize, Deserialize};

pub mod cfca;
pub mod ep;
pub mod ca_reader;

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
    pub qianzhanginfo: String,
}
impl jyframe::JsonOut for CaObj {
}