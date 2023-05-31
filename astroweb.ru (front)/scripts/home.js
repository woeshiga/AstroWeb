$(function(){
    if (!localStorage.getItem("token")){
        $("main").load("../components/not_auth.html");
    }
    else
    {
        $.ajax({
            url: `${cfg.HOST}${cfg.PORT}${cfg.GET_USER_PATH}`,
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
                $("main").load("../components/home.html");
            }
        });
    }
});
