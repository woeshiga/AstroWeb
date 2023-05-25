$(function() {
    $("#logout").click(function() {
        $.ajax({
            crossDomain: true,
            responseType: "application/json",
            url: "https://localhost:8080/api/auth/logout/",
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
