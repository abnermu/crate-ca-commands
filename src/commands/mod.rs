use serde::{Serialize, Deserialize};

pub mod cfca;
pub mod ep;
pub mod ca_reader;

/// 响应code
#[repr(i32)]
pub enum ResponseCode {
    /// 响应成功 200
    Success = 200,
    /// 响应失败 500
    Error = 500,
}
/// commands请求响应结果
#[derive(Serialize, Deserialize)]
pub struct Response<T> {
    /// 响应编码
    pub code: i32,
    /// 响应消息
    pub msg: String,
    /// 响应数据
    pub data: Option<T>,
}
impl<T> Response<T> {
    /// 返回成功响应
    fn res_ok(data: T) -> Self {
        Response::<T> {
            code: ResponseCode::Success as i32,
            msg: String::from("操作成功！"),
            data: Some(data),
        }
    }
    /// 返回失败响应
    fn res_error(msg: &str) -> Self {
        Response::<T> {
            code: ResponseCode::Error as i32,
            msg: msg.to_string(),
            data: None,
        }
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
    pub qianzhanginfo: String,
}