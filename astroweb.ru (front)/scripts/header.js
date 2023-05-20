$(function(){
    if (!localStorage.getItem("token")){
        $("header").load("../components/header.html");
    }
    else
    {
        $.ajax({
            url: "http://localhost:8000/api/get_user/",
            headers: {
                "Access-Token": localStorage.getItem("token"),
            },
            type: "GET",
            responseType: "application/json"
        })
        .done(function(data) {
            if (data.status != "OK")
            {
                localStorage.removeItem("token");
                window.location.reload()
            }
            else
            {
                $("header").load("../components/header_user.html");
            }
        });
    }
});