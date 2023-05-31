$(function() {
    $("#logout").click(function() {
        $.ajax({
            crossDomain: true,
            responseType: "application/json",
            url: `${cfg.HOST}${cfg.PORT}${cfg.LOGOUT_PATH}`,
            headers: {
                "Access-Token": localStorage.getItem("token")
            }
        })
        .done(function() {
            localStorage.clear();
            window.location.reload();
        });
    });
});
