<?php
    function send_nudes($title, $data, $link){
        $hook = "[DISCORD HERE]";
        $timestamp = date("c", strtotime("now"));

        $json_data = json_encode([
            "content" => "```".$data."```",            
            "username" => "seapodcafe",
            "embeds" => [
                [
                    // Embed Title
                    "title" => "Leaks - ".$title,
        
                    // Embed Type
                    "type" => "rich",
        
                    // URL of title link
                    "url" => $link,
        
                    // Timestamp of embed must be formatted as ISO8601
                    "timestamp" => $timestamp
                ]
            ]
        
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
        
        
        $ch = curl_init( $hook );
        curl_setopt( $ch, CURLOPT_HTTPHEADER, array('Content-type: application/json'));
        curl_setopt( $ch, CURLOPT_POST, 1);
        curl_setopt( $ch, CURLOPT_POSTFIELDS, $json_data);
        curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt( $ch, CURLOPT_HEADER, 0);
        curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1);
        
        $response = curl_exec( $ch );
        curl_close( $ch );
        return $response;
    }// end function
    
    function checkUrlExists($url, $filePath) {
        if (!file_exists($filePath)) {
            return false;
        }
    
        $fileContents = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    
        return in_array($url, $fileContents);
    }

    $_POST = json_decode(file_get_contents('php://input'), true);
    $f = fopen("debug.log","a+");
    fwrite($f,file_get_contents('php://input')."\r\n");
    fclose($f);
    $x = fopen("vuln_list.txt", "a+");
    if(!empty($_POST)) {
        if( $_POST["event_type"] == "leak"){
            switch($_POST["event_source"]){
                case "ConfigJsonHttp":
                    if(!checkUrlExists($_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/config.json", "/var/www/html/vuln_list.txt")){
                        fwrite($x, $_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/config.json\r\n");
                        fclose($x);
                        send_nudes("JSON Config publicly accessible", $_POST["summary"], $_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/config.json");
                        break;
                    }else{
                        break;
                    }
                case "DotEnvConfigPlugin":
                    if(!checkUrlExists($_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/.env", "/var/www/html/vuln_list.txt")){
                        fwrite($x, $_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/.env\r\n");
                        fclose($x);
                        send_nudes(".env publicly accessible", $_POST["summary"], $_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/.env");
                        break;
                    }else{
                        break;
                    }
                case "Log4JOpportunistic":
                    if(!checkUrlExists($_POST["protocol"]."://".$_POST["host"].":".$_POST["port"].$_POST["http"]["url"], "/var/www/html/vuln_list.txt")){
                        fwrite($x, $_POST["protocol"]."://".$_POST["host"].":".$_POST["port"].$_POST["http"]["url"]."\r\n");
                        fclose($x);
                        send_nudes("Log4J vulnerable",$_POST["summary"], $_POST["protocol"]."://".$_POST["host"].":".$_POST["port"].$_POST["http"]["url"]);
                        break;
                    }else{
                        break;
                    }
                case "GitConfigHttpPlugin":
                    if(!checkUrlExists($_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/.git/config", "/var/www/html/vuln_list.txt")){
                        fwrite($x, $_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/.git/config\r\n");
                        fclose($x);
                        send_nudes("Git config", $_POST["summary"], $_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/.git/config");
                        break;
                    }else{
                        break;
                    }
                case "DockerRegistryHttpPlugin":
                    if(!checkUrlExists($_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/v2/_catalog", "/var/www/html/vuln_list.txt")){
                        fwrite($x, $_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/v2/_catalog\r\n");
                        fclose($x);
                        send_nudes("Docker Registry exposed", $_POST["summary"], $_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/v2/_catalog");
                        break;
                    }else{
                        break;
                    }
                case "TraversalHttpPlugin":
                    if(!checkUrlExists($_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/hosts", "/var/www/html/vuln_list.txt")){
                        fwrite($x, $_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/hosts\r\n");
                        fclose($x);
                        send_nudes("Path Traversal exposed", $_POST["summary"], $_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/hosts ");
                        break;
                    }else{
                        break;
                    }
                case "SmbPlugin":
                    if(!checkUrlExists($_POST["protocol"]."://".$_POST["host"].":".$_POST["port"], "/var/www/html/vuln_list.txt")){
                        fwrite($x, $_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."\r\n");
                        fclose($x);
                        send_nudes("SMB port exposed", $_POST["summary"], $_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]);
                        break;
                    }else{
                        break;
                    }
                case "SymfonyVerbosePlugin":
                    if(!checkUrlExists($_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/frontend_dev.php/$", "/var/www/html/vuln_list.txt")){
                        fwrite($x, $_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/frontend_dev.php/$\r\n");
                        fclose($x);
                        send_nudes("Symfony verbose error exposed", $_POST["summary"], $_POST["protocol"]."://".$_POST["host"].":".$_POST["port"]."/frontend_dev.php/$");
                        break;
                    }else{
                        break;
                    }
            }
        }else{
            $f = fopen("debug.log","a+");
            fwrite($f,$_POST."\r\n");
            fclose($f);
        }
    }else{
        die(header("Location: https://xvideos.com"));
    }
?>
