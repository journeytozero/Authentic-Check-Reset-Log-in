<?php
// PHPMailer ক্লাস লোড করার জন্য (Composer ব্যবহার করলে)
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php';  // Composer এর autoload ফাইল

$mail = new PHPMailer(true);

try {
    // SMTP সেটআপ
    $mail->isSMTP();
    $mail->Host       = 'smtp.gmail.com';          // SMTP সার্ভার
    $mail->SMTPAuth   = true;                       // SMTP Authentication চালু
    $mail->Username   = 'your-email@gmail.com';    // আপনার Gmail
    $mail->Password   = 'your-app-password';       // Gmail App Password (২FA থাকলে)
    $mail->SMTPSecure = 'tls';                      // এনক্রিপশন
    $mail->Port       = 587;                        // TLS পোর্ট

    // প্রেরক ও গ্রাহক তথ্য
    $mail->setFrom('your-email@gmail.com', 'Your Name');
    $mail->addAddress('recipient@example.com', 'Recipient Name');

    // মেইল বিষয়বস্তু
    $mail->isHTML(true);
    $mail->Subject = 'টেস্ট ইমেইল PHPMailer দিয়ে';
    $mail->Body    = '<h2>হ্যালো!</h2><p>এটি PHPMailer দিয়ে পাঠানো একটি টেস্ট ইমেইল।</p>';
    $mail->AltBody = 'হ্যালো! এটি PHPMailer দিয়ে পাঠানো একটি টেস্ট ইমেইল।';//যদি আমরা body তে কোনো মেসেজ পাস না করি তখন এটা ব্যবহার করবে

    // মেইল পাঠানো
    $mail->send();
    echo 'মেইল সফলভাবে পাঠানো হয়েছে!';
} catch (Exception $e) {
    echo "মেইল পাঠানো সম্ভব হয়নি: {$mail->ErrorInfo}";
}
?>
