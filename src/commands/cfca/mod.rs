use base64::Engine;
use log as logger;

use jyframe::utils::TokenUtil;
use super::Response;

/// 获取ca完整信息
/// # 参数
/// - `with_img` 是否包含签章图片
#[tauri::command]
pub async fn cfca_init_caobj(with_img: bool) -> Result<Response<serde_json::Value>, String> {
    let mut ca_obj: super::CaObj = super::CaObj::default();
    ca_obj.by_union = true;
    ca_obj.device_num = ukeyskf::get_device_num();
    ca_obj.sign_cert = ukeyskf::get_ca_info(ukeyskf::CertInfo::CertContent, true);
    ca_obj.enc_cert = ukeyskf::get_ca_info(ukeyskf::CertInfo::CertContent, false);
    if let (Ok(sign_cert_bytes), Ok(enc_cert_bytes)) = (base64::engine::general_purpose::STANDARD.decode(&ca_obj.sign_cert), base64::engine::general_purpose::STANDARD.decode(&ca_obj.enc_cert)) {
        ca_obj.sign_cert_s_n = ukeyskf::get_cert_serial_number(&sign_cert_bytes[..]).unwrap_or(String::from(""));
        ca_obj.enc_cert_s_n = ukeyskf::get_cert_subject_key_id(&enc_cert_bytes[..]).unwrap_or(String::from(""));
        ca_obj.yxq = ukeyskf::get_cert_valid_to(&sign_cert_bytes[..]).unwrap_or(String::from(""));
        ca_obj.bfjg = ukeyskf::get_cert_issuer(&sign_cert_bytes[..]).unwrap_or(String::from(""));
        ca_obj.orgname = ukeyskf::get_cert_common_name(&sign_cert_bytes[..]).unwrap_or(String::from(""));
    }
    else {
        ca_obj.sign_cert_s_n = ukeyskf::get_ca_info(ukeyskf::CertInfo::SerialNumber, true);
        ca_obj.enc_cert_s_n = ukeyskf::get_ca_info(ukeyskf::CertInfo::SubjectKeyIdentifier, false);
        ca_obj.yxq = ukeyskf::get_ca_info(ukeyskf::CertInfo::ValidTo, true);
        ca_obj.bfjg = ukeyskf::get_ca_info(ukeyskf::CertInfo::Issuer, true);
        ca_obj.orgname = ukeyskf::get_ca_info(ukeyskf::CertInfo::CommonName, true);
    }
    // 签章图片获取
    if with_img {
        ca_obj.qianzhanginfo = get_qianzhang(&ca_obj.device_num).await;
    }
    match serde_json::to_string(&ca_obj) {
        Ok(json_str) => {
            match serde_json::from_str::<serde_json::Value>(&json_str) {
                Ok(json_val) => {
                    Ok(Response::res_ok(json_val))
                },
                Err(err) => {
                    logger::error!("error occured when convert json string to json object: {}", err);
                    Ok(Response::res_ok(serde_json::json!({})))
                },
            }
        },
        Err(err) => {
            logger::error!("error occured when convert ca_obj to json string: {}", err);
            Ok(Response::res_ok(serde_json::json!({})))
        }
    }
}
/// 数据解密
/// # 参数
/// - `enc_data` 密文
#[tauri::command]
pub fn cfca_decrypt(enc_data: &str) -> Result<Response<String>, String> {
    Ok(Response::res_ok(ukeyskf::decrypt(enc_data)))
}
/// 数据加密
/// # 参数
/// - `org_data` 原文
#[tauri::command]
pub fn cfca_encrypt(org_data: &str) -> Result<Response<String>, String> {
    Ok(Response::res_ok(ukeyskf::encrypt(org_data)))
}
/// 数据签名
/// # 参数
/// - `org_data` 原文
#[tauri::command]
pub fn cfca_sign(org_data: &str) -> Result<Response<String>, String> {
    Ok(Response::res_ok(ukeyskf::sign_data(org_data)))
}
/// 验签
/// # 参数
/// - `org_data` 原文
/// - `signed_data` 签名
#[tauri::command]
pub fn cfca_verify(org_data: &str, signed_data: &str) -> Result<Response<bool>, String> {
    Ok(Response::res_ok(ukeyskf::verify_sign(org_data, signed_data)))
}
/// 用户口令校验
/// # 参数
/// - `pwd` 用户口令值
#[tauri::command]
pub fn cfca_check_pin(pwd: &str) -> Result<Response<bool>, i32> {
    if let Some(valid) = ukeyskf::check_pin(pwd) {
        if valid.result.is_ok() {
            return Ok(Response::res_ok(true));
        }
        else {
            let retry_count_str: String = valid.retry_count.to_string();
            return Ok(Response::res_error(&retry_count_str));
        }
    }
    else {
        logger::error!("check pin failed");
    }
    Err(0)
}
/// 内部方法获取签章图片
async fn get_qianzhang(dev_num: &str) -> String {
    let url = "http://47.94.96.97:8394/api/zsqz/getQz";
    // let platform_code = "wljypt";
    let app_key = "wljypt";
    let app_secret = "wljypt001";
    let body = serde_json::json!({ "jzh": dev_num, "caType": "1" });
    let mut token = format!("{}:{}:{}", &app_key, &app_secret, TokenUtil::create_key_secret_token_default(&app_key, &app_secret));
    token = base64::engine::general_purpose::STANDARD.encode(token.as_bytes());
    let client: reqwest::Client = reqwest::Client::new();
    logger::info!("begin to request to {}, the token is {} and the body is {}.", url, &token, &body);
    match client.post(url).header("authorization", token).json(&body).send().await {
        Ok(res) => {
            match res.json::<serde_json::Value>().await {
                Ok(res_body) => {
                    logger::info!("get sign image from ca and the result is : {}", &res_body.to_string());
                    let mut qz_str_arr = vec![
                        make_qz_image_str(1, res_body["data"]["qygz"].as_str().unwrap_or("")),
                        make_qz_image_str(2, res_body["data"]["frqz"].as_str().unwrap_or("")),
                        make_qz_image_str(4, res_body["data"]["grqz"].as_str().unwrap_or("")),
                    ];
                    qz_str_arr = qz_str_arr.iter().filter(|&qz_str| qz_str != "").cloned().collect();
                    return qz_str_arr.join("|||");
                },
                Err(err) => {
                    logger::error!("error occured when try to convert response to json object: {}", err);
                },
            }
        },
        Err(err) => {
            logger::error!("error occured when try to request to {}: {}", url, err);
        }
    }
    String::from("")
}
/// 内部方法拼接签章字符串
fn make_qz_image_str(seal_type: i32, seal_image: &str) -> String {
    return if seal_image != "" {
        format!("{}-{}@@@{}", seal_type, if 1 == seal_type {"法定代表人公章"} else if 2 == seal_type {"法定代表人印鉴"} else {"个人签名"}, seal_image)
    }
    else {
        String::from("")
    };
}
