
use std::sync::{Arc, Mutex};
use tauri::State;
use log as logger;

use jyframe::{AppState, Response, JsonOut};

const DEFAULT_HOST: &str = "http://127.0.0.1";
const DEFAULT_PORT: i32 = 11345;
const DEFAULT_CA_TYPE: &str = "260";
const DEFAULT_PDF_TYPE: i32 = 200;
const DEFAULT_LICENSEKEY: &str = "3LKzp8gknhTBrYi1xoUCHJs3rdbeMSjTabufvyVSkis5s/47y9PRwnoy923L09tYjUhxtrGxXLDV1lAGAP5t7r/LlRKM3xe39elUfaQOkJrpwBYB5ZK4aWKS7bgkuKGXIP7v XxFp9rIWv8JothGtVr7J1JUUX4tBHj6pyYLGZhI7CTszRbhDgZla7kdKPXghzCfbK8ZdKHhh B XD qXZyYC4DkLBF BkY4R5DTfBcX1ItMTfsfo2mhY6UPgeY2umx9F0cUASpSVy13IyHOiQ: =*3LKzp8gknhTBrYi1xoUCHJs3rdbeMSjTabufvyVSkis5s/47y9PRwnoy923L09tYjUhxtrGxXLDV1lAGAP5t7r/LlRKM3xe39elUfaQOkJrpwBYB5ZK4aWKS7bgkuKGXIP7v XxFp9rIWv8JothGtVr7J1JUUX4tBHj6pyYLGZhI7CTszRbhDgZla7kdKPXgxxyzfziZm/FQAUGnK4ifzkRLLG6YpxZYOINp4qkUNqUi2uvKqfH/q9PMHaZ5ECSJ6WapmSMITA9zDY/OHoxnAQ==*3LKzp8gknhTBrYi1xoUCHJs3rdbeMSjTabufvyVSkis5s/47y9PRwnoy923L09tYjUhxtrGxXLDV1lAGAP5t7r/LlRKM3xe39elUfaQOkJrpwBYB5ZK4aWKS7bgkuKGXIP7v XxFp9rIWv8JothGtVr7J1JUUX4tBHj6pyYLGZhI7CTszRbhDgZla7kdKPXghzCfbK8ZdKHhh B XD qXTohr5XECgzqJA479oAUol0xddHNtNYPtIX 6LM4puWbSW27YI fuz5INVC/LLx/ug==*3LKzp8gknhTBrYi1xoUCHJs3rdbeMSjTabufvyVSkis5s/47y9PRwnoy923L09tYjUhxtrGxXLDV1lAGAP5t7r/LlRKM3xe39elUfaQOkJrpwBYB5ZK4aWKS7bgkuKGXIP7v XxFp9rIWv8JothGtVr7J1JUUX4tBHj6pyYLGZhI7CTszRbhDgZla7kdKPXghzCfbK8ZdKHhh B XD qXSmR3yPjvO09hn3L nmWlt9sNQoVmGOQzBPa3aLKbcs9HhZmXz4gvaQFRZvvr18CeQ==*|ZXBvaW50LWxpY2Vuc2UDMzY1eyJzcGxpdE1hcmsiOiJKRFE9IiwiYXBwbHlUaW1lIjoxNjA3MDQ2OTA3MTQ3LCJwdWJsaWNLZXlzIjoiTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDUmxmVjc2VHRwb0E0TTBNL0huVTl3MmloYitkejJTNmNra20vSEwvVG5SQ3JNdkNUSVR3c0tWai9XQ1dvQVh5dW1OeldkVFI3dThhNFhWSFRqVE5rS0xxMnAzbzVWNFVLNVBWWS9qc0dsakl1dC92T3Q0bk5KVER3ZkdSdE8wa0Fwcm4rZ2Z3Q3Q1MDE1VU9BVjNnbTcyZGFWZzk3TkxFMUgyUktwUjRUMDhRSURBUUFCIiwiZXhwaXJlVGltZSI6MzMxNjM5NTU3MDQ3OTEsIm1kNSI6ImFkY2E5NDQxNmRmYzBlMjNmZjY1ZWFkMjFkZWQ4ZTg0Iiwic291cmNlRGF0YSI6bnVsbH0NMTYwNzA0NjkwNzE0Nw4zMzE2Mzk1NTcwNDc5MQMxNjIwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJGV9XvpO2mgDgzQz8edT3DaKFv53PZLpySSb8cv9OdEKsy8JMhPCwpWP9YJagBfK6Y3NZ1NHu7xrhdUdONM2QouranejlXhQrk9Vj OwaWMi63 863ic0lMPB8ZG07SQCmuf6B/AK3nTXlQ4BXeCbvZ1pWD3s0sTUfZEqlHhPTxAgMBAAGAXzvKs0traHBmJrGYJjMZrrQbDXkvwS8YpqKITId34e1G2dSmaHAUHDxbAQWDPoIqxTpicYcooxsbtkRvlzcG51zQopGlB4v6yHf73QPTyNAy3q3IpZjSyTQscDRnB16XaWj90O7a/LINrkcyB4aMB5UoXQ ZOHrDlL97WXx67dmARow8t8L0tadcueUbFSggHDEzSEJy7V FesT8XRidk8GcLT2xCMih6MO ZwJZYqIupz2raW2aCKtKX M0NQPou9HYxjv1n0Jp9SzbWWPGJhG1UcK2ahxMxVDj78jWg53ByB0RLU86cR9iAk9VczNhXHEwztlwAwIWh2awDk103NqAkQeFe19M0BCSrOl8D5KvksLH9Mu5tNB/x0wtTYrK5z2o7lvwcvLbJ64ie4QK04kfWPPFD4IE8q01kUA7wjqY5cKKWkUZ5Y/IBAIE2mN9U5TEhJU7psE0 02Jb1RF1mBuyR4gX8SS7DtzgWF4JAxLCA1djMJgbLJNFNIN0GcnINiAOCn0o6yrJadVm BsIR4bnrIYag2LyIRuUB0L8kGOBBQJ1qFcd7 uZgN4FG adYHsO486vQtasHJjAWCTerCXvCDRL7bs0k28SNRQocoT/uLTh001l izGp4fcp2zaXk5mgzKrEVd46OpzLd6/7Y2uHbU4wzwyLldKqY3l9zMsX6AcMU8QQ6KbDrBS Rn TpOJXWtAKKhYBlZS4DI6ylgyq8DwVdJvd27HerAnlyKKFUQ3EYMTHpDHtkwKlaRia2HxfnQp6rJ7SKffeL2RIaITdcjJ3nQZHxaJJXlCpLc2b6XMCKQjF9njqYFB4R9pj8U9oyclLBPpSy0nhpyCeNluYCAgSYCCsAnofUPJIn4GPHTgya3cOG1hsgQlXJuvllvRtu7 g9eTP9x4f638BjS47YaakITVecHN5 FHV73rg60jZruAdnomKyEKPg7j5ALg7qDyEZndOwY6tn0u0yBqqRZHQG9a XeGGnPwSZ9T2YD7Ej/T6CbWMl8DEnizY65mnmAGBoMRVQgGqX1Jaw1YVN30xnhvdzAE oCzoFw0ZdCoM13f2iPgJWZ60pB1SdL1YRfItKw4AJ/SlsDAPqsOemAGrqFIeYJ5urEd30X1/8ofmTeUt6/za7MipJnFwpM3HOF1JEn2 WMBUtTcY0QadIz/T9Vhq5PFdBPl9AZaKIFQSEA";

/// 获取ca完整信息
/// # 参数
/// - `with_img` 是否包含签章图片
#[tauri::command]
pub async fn ep_init_caobj(state: State<'_, Arc<Mutex<AppState>>>, with_img: bool) -> Result<Response<serde_json::Value>, String> {
    if test_port(&state).await {
        ca_init(AppState::get_ep_ca_port(&state)).await;
        let mut ca_obj = super::CaObj::default();
        ca_obj.enc_cert_s_n = get_cert_object(AppState::get_ep_ca_port(&state), "CertSubjectKeyID", "skid").await;
        ca_obj.sign_cert_s_n = get_cert_object(AppState::get_ep_ca_port(&state), "ClientSignCertSN", "sn").await;
        ca_obj.yxq = get_cert_object(AppState::get_ep_ca_port(&state), "CertYouXiaoQi", "yxq").await;
        ca_obj.sign_cert = get_cert_object(AppState::get_ep_ca_port(&state), "SignCert", "signcert").await;
        ca_obj.enc_cert = get_cert_object(AppState::get_ep_ca_port(&state), "EncCert", "decryptcert").await;
        ca_obj.device_num = get_cert_object(AppState::get_ep_ca_port(&state), "DeviceNum", "devicenum").await;
        ca_obj.bfjg = get_cert_object(AppState::get_ep_ca_port(&state), "Bfjg", "dn").await;
        ca_obj.orgname = get_cert_object(AppState::get_ep_ca_port(&state), "ClientSignCertCN", "cn").await;
        if with_img {
            let qz_req = serde_json::json!({
                "body": {
                    "qrinfo": {
                        "ext": {
                            "PDFType": DEFAULT_PDF_TYPE,
                            "LicenseKey": DEFAULT_LICENSEKEY,
                        },
                        "qrcodetype": "QianZhangInfo",
                    }
                }
            });
            let qz_data = post_data(AppState::get_ep_ca_port(&state), qz_req).await;
            if let Some(qz) = qz_data["body"]["qrinfo"]["ext"]["Image"].as_str() {
                ca_obj.qianzhanginfo = super::EnQianZhangInfo::QianZhangStr(qz.to_string());
            }
        }
        Ok(Response::res_ok(ca_obj.to_json()))
    }
    else {
        return Ok(Response::res_error("程序启动失败，请重装驱动后重启电脑尝试。"));
    }
}
/// 数据加密
/// # 参数
/// - `org_data` 原文
#[tauri::command]
pub async fn ep_encrypt(state: State<'_, Arc<Mutex<AppState>>>, org_data: &str) -> Result<Response<String>, String> {
    if test_port(&state).await {
        ca_init(AppState::get_ep_ca_port(&state)).await;
        let req_body = serde_json::json!({
            "body": {
                "qrinfo": {
                    "decryptobjects": [{"org": org_data}],
                    "ext": {
                        "CertPath": ""
                    },
                    "qrcodetype": "Encrypt",
                }
            }
        });
        let rtn = post_data(AppState::get_ep_ca_port(&state), req_body).await;
        if let Some(encrypted) = rtn["body"]["qrinfo"]["decryptobjects"][0]["encryed"].as_str() {
            return Ok(Response::res_ok(encrypted.to_string()));
        }
        else {
            logger::warn!("ep server ecnrypt response struct resolve failed: {}", &rtn.to_string());
        }
    }
    else {
        return Ok(Response::res_error("程序启动失败，请重装驱动后重启电脑尝试。"));
    }
    Ok(Response::res_ok(String::from("")))
}
/// 数据解密
/// # 参数
/// - `enc_data` 密文
#[tauri::command]
pub async fn ep_decrypt(state: State<'_, Arc<Mutex<AppState>>>, enc_data: &str) -> Result<Response<String>, String> {
    if test_port(&state).await {
        ca_init(AppState::get_ep_ca_port(&state)).await;
        let req_body = serde_json::json!({
            "body": {
                "qrinfo": {
                    "decryptobjects": [{"encryed": enc_data}],
                    "qrcodetype": "Decrypt",
                }
            }
        });
        let rtn = post_data(AppState::get_ep_ca_port(&state), req_body).await;
        if let Some(decrypted) = rtn["body"]["qrinfo"]["decryptobjects"][0]["org"].as_str() {
            return Ok(Response::res_ok(decrypted.to_string()));
        }
        else {
            logger::warn!("ep server decrypt response struct resolve failed: {}", &rtn.to_string());
        }
    }
    else {
        return Ok(Response::res_error("程序启动失败，请重装驱动后重启电脑尝试。"));
    }
    Ok(Response::res_ok(String::from("")))
}
/// 数据签名
/// # 参数
/// - `org_data` 原文
#[tauri::command]
pub async fn ep_sign(state: State<'_, Arc<Mutex<AppState>>>, org_data: &str) -> Result<Response<String>, String> {
    if test_port(&state).await {
        ca_init(AppState::get_ep_ca_port(&state)).await;
        let req_body = serde_json::json!({
            "body": {
                "qrinfo": {
                    "signatureobjects": [{"org": org_data}],
                    "qrcodetype": "SignData",
                }
            }
        });
        let rtn = post_data(AppState::get_ep_ca_port(&state), req_body).await;
        if let Some(signed) = rtn["body"]["qrinfo"]["signatureobjects"][0]["signed"].as_str() {
            return Ok(Response::res_ok(signed.to_string()));
        }
        else {
            logger::warn!("ep server sign response struct resolve failed: {}", &rtn.to_string());
        }
    }
    else {
        return Ok(Response::res_error("程序启动失败，请重装驱动后重启电脑尝试。"));
    }
    Ok(Response::res_ok(String::from("")))
}
/// 验签
/// # 参数
/// - `org_data` 原文
/// - `signed_data` 签名
/// - `sign_cert` 签名证书
#[tauri::command]
pub async fn ep_verify(state: State<'_, Arc<Mutex<AppState>>>, org_data: &str, signed_data: &str, sign_cert: &str) -> Result<Response<bool>, String> {
    if test_port(&state).await {
        ca_init(AppState::get_ep_ca_port(&state)).await;
        let req_body = serde_json::json!({
            "body": {
                "qrinfo": {
                    "signatureobjects": [{
                        "org": org_data,
                        "signed": signed_data,
                        "cert": sign_cert,
                    }],
                    "qrcodetype": "VerifyData",
                }
            }
        });
        let rtn = post_data(AppState::get_ep_ca_port(&state), req_body).await;
        if let Some(verify) = rtn["body"]["qrinfo"]["signatureobjects"][0]["desc"].as_str() {
            return Ok(Response::res_ok("1" == verify));
        }
        else {
            logger::warn!("ep server verify response struct resolve failed: {}", &rtn.to_string());
        }
    }
    else {
        return Ok(Response::res_error("程序启动失败，请重装驱动后重启电脑尝试。"));
    }
    Ok(Response::res_ok(false))
}
/// 用户口令校验
/// # 参数
/// - `pwd` 用户口令值
#[tauri::command]
pub async fn ep_check_pin(state: State<'_, Arc<Mutex<AppState>>>, pwd: &str) -> Result<Response<bool>, i32> {
    if test_port(&state).await {
        ca_init(AppState::get_ep_ca_port(&state)).await;
        let req_body = serde_json::json!({
            "body": {
                "qrinfo": {
                    "ext": {
                        "pwd": pwd,
                    },
                    "qrcodetype": "CheckPin",
                }
            }
        });
        let rtn = post_data(AppState::get_ep_ca_port(&state), req_body).await;
        if let Some(valid) = rtn["body"]["qrinfo"]["ext"]["pwd"].as_str() {
            return Ok(Response::res_ok("1" == valid));
        }
        else {
            logger::warn!("ep server check pin response struct resolve failed: {}", &rtn.to_string());
        }
    }
    else {
        return Ok(Response::res_error("程序启动失败，请重装驱动后重启电脑尝试。"));
    }
    Ok(Response::res_ok(false))
}

/// 内部方法获取证书对象的某个值
async fn get_cert_object(port: i32, qrtype: &str, result_key: &str) -> String {
    let data = post_data(port, prepare(qrtype)).await;
    if let Some(rtn) = data["body"]["qrinfo"]["certobject"][result_key].as_str() {
        return rtn.to_string();
    }
    else {
        logger::warn!("ep server cert object response struct resolve failed: {}", &data.to_string());
    }
    String::from("")
}
/// 内部方法CA初始化
async fn ca_init(port: i32) -> bool {
    let data = post_data(port, prepare("CAInit")).await;
    if let Some(qrstatus) = data["body"]["qrstatus"].as_str() {
        return qrstatus == "1";
    }
    else {
        logger::warn!("ep server ca init response struct resolve failed: {}", &data.to_string());
    }
    false
}
/// 内部方法端口测试
async fn test_port(state: &State<'_, Arc<Mutex<AppState>>>) -> bool {
    // 260 11345 http://127.0.0.1
    let mut port: i32 = AppState::get_ep_ca_port(state);
    if port == 0 {
        port = DEFAULT_PORT;
    }
    if connect(port).await["CAType"].as_str().unwrap_or("0") == DEFAULT_CA_TYPE {
        AppState::set_ep_ca_port(port, state);
        return true;
    }
    else {
        logger::warn!("try to connect ep server with port {} failed, try next port", port);
        for i in 0..10 {
            port = DEFAULT_PORT + i;
            if connect(port).await["CAType"].as_str().unwrap_or("0") == DEFAULT_CA_TYPE {
                AppState::set_ep_ca_port(port, state);
                return true;
            }
            else {
                logger::warn!("try to connect ep server with port {} failed, try next port", port);
            }
        }
    }
    false
}
/// 内部方法，通用请求body生成
fn prepare(qrtype: &str) -> serde_json::Value {
    serde_json::json!({
        "body": {
            "qrinfo": {
                "qrcodetype": qrtype,
            }
        }
    })
}
/// 内部方法请求数据
async fn post_data(port: i32, body: serde_json::Value) -> serde_json::Value {
    let client = reqwest::Client::new();
    match client.post(format!("{}:{}", DEFAULT_HOST, port)).json(&body).send().await {
        Ok(res) => {
            match res.json::<serde_json::Value>().await {
                Ok(body) => {
                    return body.clone();
                },
                Err(err) => {
                    logger::error!("try to convert ep response to json object failed: {}", err);
                }
            }
        },
        Err(err) => {
            logger::error!("try to request ep server {} with data {} failed: {}", format!("{}:{}", DEFAULT_HOST, port), &body.to_string(), err);
        }
    }
    serde_json::json!({})
}
/// 内部方法连接本地端口
async fn connect(port: i32) -> serde_json::Value {
    match reqwest::get(format!("{}:{}", DEFAULT_HOST, port.to_string())).await {
        Ok(res) => {
            match res.json::<serde_json::Value>().await {
                Ok(rtn) => {
                    return rtn.clone();
                },
                Err(err) => {
                    logger::error!("try to convert ep response to json object failed: {}", err);
                }
            }
        },
        Err(err) => {
            logger::error!("try to get ep server {} failed: {}", format!("{}:{}", DEFAULT_HOST, port), err);
        }
    }
    serde_json::json!({"CAType": "0"})
}
