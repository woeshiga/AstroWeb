$(function() {
    $("#loginBtn").click(function() {
        let login = $("#login").val();
        let password = $("#password").val();
        $.ajax({
            crossDomain: true,
            responseType: "application/json",
            url: "http://localhost:8000/api/auth/login/?login="+login+"&password="+password,
            type: "POST"
        })
        .done(function(data) {
            localStorage.clear()
            localStorage.setItem("login", data.data.login);
            localStorage.setItem("token", data.data.token);
            localStorage.setItem("status", data.data.status);
            window.location.replace("/");
        });
    });
});