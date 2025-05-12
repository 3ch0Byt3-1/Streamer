$(document).ready(function () {
    console.log('status ok');

    $.ajax({
        type: "POST",
        url: "/get-process",
        success: function (response) {
            if(response.status == 200) {
                $("#onlinebtn").text("Online").removeClass('disable').addClass('enable');
            } else {
                $("#onlinebtn").text("Offline").removeClass('enable').addClass('disable');
            }
        }
    });

});