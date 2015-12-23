/**
 * Created by Administrator on 15-5-7.
 */

var windowHeight = $(window).height();
var windowWidth= $(window).width();

$(function(){
	//index.html撑起DIV
	//$(".login_main").height(windowHeight);
	//$(".login_main").width(windowWidth);
	createCode();
});


/**
 * 验证form表单
 * @returns
 */
function validateForm(){
	var username = $("#username").val();
	var password = $("#password").val();
	var checkCode = $("#check_code").text();
	var inputCheckCode = $("#validate_code").val();
	if(username == null || username == '' || username == undefined){
  	    alert("用户名不能为空，请重新输入!");
		return false;
	}
	if(password == null || password == '' || password == undefined){
  	    alert("用户名不能为空，请重新输入!");
		return false;
	}
	if(checkCode != inputCheckCode){
  	    alert("验证码输入有误，请重新输入!");
		//重新生成验证码
		createCode();
		return false
	}
    return true;
}

/**
 * 生成验证码
 * @returns
 */
function createCode(){
    var code="" ;
    var codeLength=4;
    var selectChar = [0,1,2,3,4,5,6,7,8,9,'A','B','C','D','E','F','G','H','J','K','L','M','N','P','Q',
        'R','S','T','U','V','W','X','Y','Z'];
    for(var i=0;i<codeLength;i++){
        var charIndex = Math.floor(Math.random()*32);
        code +=selectChar[charIndex];
    }
    if(code.length!=codeLength){
        createCode();
    }
    $("#check_code").text(code);
}

/**
 * onkeypress事件时验证码校验
 */
function validateCode(obj){
	var inputCode = $("#validate_code").val();
	var checkCode= $("#check_code").text();
    if(inputCode == null || inputCode == undefined || $.trim(inputCode).length < 4){
    	return false;
    }else if($.trim(inputCode).length ==4){
    	if(inputCode == checkCode){
    		$("#validate_result").removeClass("validate_result_error glyphicon-remove").addClass("validate_result_right glyphicon-ok");
    	}else{
    		$("#validate_result").removeClass("validate_result_right glyphicon-ok").addClass("validate_result_error glyphicon-remove");    		
    	}
    }else if($.trim(inputCode).length > 4){
		$("#validate_result").removeClass("validate_result_right glyphicon-ok").addClass("validate_result_error glyphicon glyphicon-remove");    		   	
    }

}
