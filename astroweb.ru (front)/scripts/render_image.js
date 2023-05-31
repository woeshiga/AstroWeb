$(function() {

    var imageArray = null;
    $.ajax({
        crossDomain: true,
        url: `${cfg.HOST}${cfg.PORT}${cfg.GET_IMAGE_PATH}`,
        headers: {
            "Access-Token": localStorage.getItem("token")
        },
        responseType: "application/json"
    })
    .done(function(data) {
        imageArray = data.image[0];

        let byteArray = new Uint8Array(imageArray);

        console.log(byteArray);

        // Создаем Blob из массива байтов
        const blob = new Blob([byteArray], { type: 'image/jpeg' });

        // Создаем URL из Blob
        const url = URL.createObjectURL(blob);

        // Создаем новый объект Image
        const img = new Image();

        // Задаем src объекта Image равным URL
        img.src = url;

        // Вставляем изображение в DOM
        document.querySelector(".image").appendChild(img);
    });


});
