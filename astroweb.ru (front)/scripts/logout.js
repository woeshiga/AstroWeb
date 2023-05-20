$(function() {
    $("#logout").click(function() {
        $.ajax({
            crossDomain: true,
            responseType: "application/json",
            url: "http://localhost:8000/api/auth/logout/",
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