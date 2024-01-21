package org.zerock.b01.dto.upload;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UploadResultDTO {

    private String uuid;

    private String fileName;

    private boolean img;

    public String getLink(){
        if(img){
            return "S_"+uuid+"_"+fileName;
        }else{
            return uuid+"_"+fileName;
        }
    }
}
