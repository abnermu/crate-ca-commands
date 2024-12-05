use std::{io::Cursor, time::Duration};
use base64::Engine;
use image::GenericImageView;
use serde::{Serialize, Deserialize};
use log as logger;

use jyframe::utils::TokenUtil;

/// token返回结果对象
#[derive(Default, Serialize, Deserialize)]
pub struct TokenResult {
    /// 平台编码
    pub platformcode: String,
    /// token值
    pub token: String,
    /// 过期时间
    pub expired: i64,
}
///token用途枚举
enum TokenFlag {
    LiaoYiTong,
    Share,
    Union,
}
impl TokenFlag {
    fn from_str(flag: &str) -> Self {
        if "share" == flag {
            return Self::Share;
        }
        else if "un" == flag {
            return Self::Union;
        }
        else {
            return Self::LiaoYiTong;
        }
    }
    fn to_token(&self) -> &str {
        match &self {
            Self::LiaoYiTong => "jgw001@@@jgw001@@@jgwlytgy001",
            Self::Share => "wljypt@@@wljypt@@@wljypt001",
            Self::Union => "wljypt@@@wljypt@@@wljypt001",
        }
    }
    fn is_lyt(&self) -> bool {
        match self {
            Self::LiaoYiTong => true,
            _ => false,
        }
    }
    fn is_shar_usb(&self) -> bool {
        match self {
            Self::Union => true,
            _ => false,
        }
    }
}
/// CA组件生成token
/// # 参数
/// - `flag` token用途：'liaoyitong' | 'share' | 'un' | 'faceSmrz' | 'face'
#[tauri::command]
pub fn ca_reader_token(flag: &str) -> Result<TokenResult, String> {
    let token_flag = TokenFlag::from_str(flag);
    let mut token_obj = TokenResult::default();
    let mut expire_time = chrono::Local::now();
    let token_info: Vec<&str> = token_flag.to_token().split("@@@").collect();
    token_obj.platformcode = token_info[0].to_string();
    let token_val = TokenUtil::create_key_secret_token_default(token_info[1], token_info[2]);
    token_obj.token = if token_flag.is_lyt() {
        token_val
    } else if token_flag.is_shar_usb() {
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}:{}", token_info[1], token_info[2], token_val).as_bytes())
    }
    else {
        String::from("")
    };
    expire_time = expire_time + chrono::Duration::minutes(TokenUtil::TOKEN_VALID_MINUTES as i64);
    token_obj.expired = expire_time.timestamp_millis();
    Ok(token_obj)
}
/// CA组件请求代理接口
/// # 参数
/// - `method` 请求方法
/// - `url` 请求地址（该地址只是后半部分，还需要做正则替换）
/// - `options` 请求选项
#[tauri::command]
pub async fn ca_reader_proxy(method: &str, url: &str, options: serde_json::Value) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::new();
    let real_url: String = get_url_real(url);
    let mut req_builder = client.request(if "get" == method.to_lowercase() {reqwest::Method::GET} else {reqwest::Method::POST}, &real_url);
    if let Some(timeout) = options["timeout"].as_u64() {
        req_builder = req_builder.timeout(Duration::from_millis(timeout));
    }
    if let Some(headers) = options["headers"].as_object() {
        for header_key in headers.keys() {
            if let Some(header_val) = headers.get(header_key) {
                req_builder = req_builder.header(header_key, header_val.as_str().unwrap_or(""));
            }
        }
    }
    if "get" != method.to_lowercase() {
        req_builder = req_builder.json(&options["data"]);
    }
    match req_builder.send().await {
        Ok(res) => {
            match res.json::<serde_json::Value>().await {
                Ok(res_body) => return Ok(res_body),
                Err(err) => {
                    logger::error!("try to resolve the proxy result body to ca object failed: {}", err);
                }
            };
        },
        Err(err) => {
            logger::error!("try to proxy ca-reader {} with headers {} and body {} failed: {}", &real_url, &options["headers"].to_string(), &options["data"].to_string(), err);
        }
    };
    Ok(serde_json::json!({}))
}
/// CA组件，中招扫码签章生成二维码
#[tauri::command]
pub async fn ca_reader_zz_qr_create() -> Result<serde_json::Value, String> {
    Ok(jyframe::ZhongZhaoUtil::zz_common_request(&jyframe::ZhongZhaoUtil::zz_build_cebs().to_string(), "generateElectronicSealSignatureQRCode").await)
}
/// CA组件，中招扫码签章查询二维码状态
#[tauri::command]
pub async fn ca_reader_zz_qr_status(dto: serde_json::Value) -> Result<serde_json::Value, String> {
    let body_obj = serde_json::json!({
        "tid": dto["tid"].as_str().unwrap_or(""),
        "cebsSdkProperties": jyframe::ZhongZhaoUtil::zz_build_cebs(),
        "jwtProperties": serde_json::json!({
            "key": jyframe::ZhongZhaoUtil::DEFAULT_JWT_KEY,
            "tradingSystemKey": jyframe::ZhongZhaoUtil::DEFAULT_JWT_TRADING_SYSTEM_KEY,
        }),
    });
    Ok(jyframe::ZhongZhaoUtil::zz_common_request(&body_obj.to_string(), "queryQRCodeScannedStatus").await)
}
/// CA组件，中招扫码签章查询二维码结果
#[tauri::command]
pub async fn ca_reader_zz_qr_result(dto: serde_json::Value) -> Result<serde_json::Value, String> {
    Ok(jyframe::ZhongZhaoUtil::zz_common_request(&serde_json::json!({"tid": dto["tid"].as_str().unwrap_or("")}).to_string(), "getElectronicSealSignatureUserInfo").await)
}
/// CA组件，中招扫码签章查询二维码签章图片
#[tauri::command]
pub async fn ca_reader_zz_qr_seals(dto: serde_json::Value) -> Result<serde_json::Value, String> {
    let body_obj = serde_json::json!({
        "tid": dto["tid"].as_str().unwrap_or(""),
        "pid": dto["pid"].as_str().unwrap_or(""),
        "sealBelongType": dto["sealBelongType"].as_str().unwrap_or(""),
        "orgTransactionCode": dto["orgTransactionCode"].as_str().unwrap_or(""),
        "personalTransactionCode": dto["personalTransactionCode"].as_str().unwrap_or(""),
        "accessToken": dto["accessToken"].as_str().unwrap_or(""),
        "tradingSystemCode": jyframe::ZhongZhaoUtil::DEFAULT_TRADING_SYSTEM_CODE,
        "orgCode": dto["orgCode"].as_str().unwrap_or(""),
        "idCardHash": dto["idCardHash"].as_str().unwrap_or(""),
    });
    let mut rtn = jyframe::ZhongZhaoUtil::zz_common_request(&body_obj.to_string(), "getUserSeals").await;
    if let Some(rtn_data) = rtn["data"].as_array_mut() {
        if rtn_data.len() > 0 {
            // 图片缩放
            let max_width: f64 = 150.0 * (dto["dpi"].as_f64().unwrap_or(96.0)) / 72.0;
            for img_obj in rtn_data {
                if let Some(seal_img) = img_obj["sealImage"].as_str() {
                    img_obj["sealImage"] = serde_json::json!(resize_seal_image(seal_img, max_width));
                }
                else {
                    logger::warn!("there is not user sealImage");
                }
            }
        }
        else {
            logger::warn!("there is not user seals");
        }
    }
    else {
        logger::warn!("there is not user seals");
    }
    Ok(rtn)
}
/// 内部方法，替换url为实际的请求地址
fn get_url_real(url: &str) -> String {
    let reg_ca_reader_pccert = regex::Regex::new(r"^/careader/pccert").unwrap();
    let reg_ca_reader = regex::Regex::new(r"^/careader").unwrap();
    let reg_liaoyitong = regex::Regex::new(r"^/liaoyitong").unwrap();
    let reg_face_smrz = regex::Regex::new(r"^/face/smrz").unwrap();
    let reg_face = regex::Regex::new(r"^/face").unwrap();
    if reg_ca_reader_pccert.is_match(url) {
        return reg_ca_reader_pccert.replace(url, "http://114.115.181.95:8070/api").to_string();
    }
    else if reg_ca_reader.is_match(url) {
        return reg_ca_reader.replace(url, "http://47.94.96.97:8394/api").to_string();
    }
    else if reg_liaoyitong.is_match(url) {
        return reg_liaoyitong.replace(url, "http://lyt.lnwlzb.com/EpMCertService").to_string();
    }
    else if reg_face_smrz.is_match(url) {
        return reg_face_smrz.replace(url, "http://smrz.lnwlzb.com/api/smrz/smrz").to_string();
    }
    else if reg_face.is_match(url) {
        return reg_face.replace(url, "https://lnwlzj.capass.cn/ca/cloudSignatureExpireStatus").to_string();
    }
    url.to_string()
}
/// 内部方法图片缩放
fn resize_seal_image(seal_img: &str, max_width: f64) -> String {
    match base64::engine::general_purpose::STANDARD.decode(seal_img) {
        Ok(img_bytes) => {
            match image::ImageReader::new(Cursor::new(&img_bytes[..])).with_guessed_format() {
                Ok(img_reader) => {
                    match img_reader.decode() {
                        Ok(mut img_ins) => {
                            let (ori_width, ori_height) = img_ins.dimensions();
                            if ori_width as f64 > max_width {
                                let scale: f64 = max_width / ori_width as f64;
                                let scaled_width = ori_width as f64 * scale;
                                let scaled_height = ori_height as f64 * scale;
                                img_ins = img_ins.resize(scaled_width as u32, scaled_height as u32, image::imageops::FilterType::Lanczos3);
                                let mut scaled_img_bytes: Vec<u8> = Vec::new();
                                match img_ins.write_to(&mut Cursor::new(&mut scaled_img_bytes), image::ImageFormat::Png) {
                                    Ok(_) => return base64::engine::general_purpose::STANDARD.encode(&scaled_img_bytes[..]),
                                    Err(err) => {
                                        logger::error!("write resized image to bytes failed: {}", err);
                                    }
                                }
                            }
                            else {
                                logger::info!("the seal image no need to be resized");
                            }
                        },
                        Err(err) => {
                            logger::error!("get dynamic image instance failed: {}", err);
                        }
                    }
                },
                Err(err) => {
                    logger::error!("create image reader failed: {}", err);
                }
            }
        },
        Err(err) => {
            logger::error!("try to convert sealImage from base64 to bytes failed: {}", err);
        }
    }
    seal_img.to_string()
}