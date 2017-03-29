<?php 
namespace common\components;
class Sign {
 
    /**
     * 获取(生成)数据签名
     * 
     * @param  array  $param  签名数组
     * @param  string $secretKey      安全校验码
     * @param  string $sign_type 签名类型
     * @return string        签名字符串
     */
    public static function getSign($param, $secretKey, $sign_type = 'MD5'){
        //去除数组中的空值和签名参数(sign/sign_type)
        $param = self::paramFilter($param);
        //按键名升序排列数组
        $param = self::paramSort($param);
        //把数组所有元素，按照“参数=参数值”的模式用“&”字符拼接成字符串
        $param_str = self::createLinkstring($param);
        //把拼接后的字符串再与安全校验码直接连接起来
        $param_str = $param_str . $secretKey;
        //创建签名字符串
        return self::createSign($param_str, $secretKey, $sign_type);
    }
     
    /**
     * 校验数据签名
     *
     * @param  string $sign  接口收到的签名
     * @param  array  $param  签名数组
     * @param  string $secretKey      安全校验码
     * @param  string $sign_type 签名类型
     * @return boolean true正确，false失败
     */
    public static function checkSign($sign, $param, $secretKey, $sign_type = 'MD5'){
        return strtolower($sign) == self::getSign($param, $secretKey, $sign_type);
    }
     
    /**
     * 去除数组中的空值和签名参数
     * 
     * @param  array $param 签名数组
     * @return array        去掉空值与签名参数后的新数组
     */
    private static function paramFilter($param){
        $param_filter = array();
        foreach ($param as $key => $val) {
            if($key == 'sign' || $key == 'sign_type' || !strlen($val)){
                continue;
            }
            $param_filter[$key] = $val;
        }
        return $param_filter;
    }
     
    /**
     * 按键名升序排列数组
     * 
     * @param  array $param 排序前的数组
     * @return array        排序后的数组
     */
    private static function paramSort($param){
        ksort($param);
        reset($param);
        return $param;
    }
     
    /**
     * 把数组所有元素，按照“参数=参数值”的模式用“&”字符拼接成字符串
     * 
     * @param  array $param 需要拼接的数组
     * @return string       拼接完成以后的字符串
     */
    private static function createLinkstring($param){
        $str = '';
        foreach ($param as $key => $val) {
            $str .= "{$key}={$val}&";
        }
        //去掉最后一个&字符
        $str = substr($str, 0, strlen($str) - 1);
        //如果存在转义字符，那么去掉转义
        if(get_magic_quotes_gpc()){
            $str = stripslashes($str);
        }
        return $str;
    }
     
    /**
     * 创建签名字符串
     * 
     * @param  string $param 需要加密的字符串
     * @param  string $type  签名类型 默认值：MD5
     * @return string 签名结果
     */
    private static function createSign($param, $secretKey, $type = 'MD5'){
        $type = strtolower($type);
        if($type == 'md5'){
            return md5(mb_convert_encoding($param, "utf8", "auto"));
        }
        if($type == 'hash_hmac')
        {
            return hash_hmac("md5",strtolower($param) , $secretKey);
        }
        if($type == 'dsa'){
            exit('DSA 签名方法待后续开发，请先使用MD5签名方式');
        }
        exit("接口暂不支持" . $type . "类型的签名方式");
    }

}
