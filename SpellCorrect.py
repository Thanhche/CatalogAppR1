def spelling_corrector(s1,s2):
    
#function: find_mismatch
    def find_mismatch(s1,s2):
        
        # Lowercase parameters
        str01 = s1.lower()[:]    
        str02 = s2.lower()[:]
        
        # str01 and str02 are similar absolutely
        if str01 == str02:        
            result = 0
        
        # str01 and str02 are similar length
        elif len(str01) == len(str02):
            
            counter_mismath = 0
            
            for i in range(0, len(str01)):
                if str01[i] != str02[i]:
                    counter_mismath += 1
                    
            # If there is 1 mismath
            if counter_mismath == 1:
                result = 1

            # If there is more than 2 mismaths
            else:
                result = 2
                
        # str01 and str02 are not similar length
        else:
            result = 2


        return result

#function: single_insert_or_delete

    def single_insert_or_delete(s1, s2):

        str01 = s1.lower()[:]
        str02 = s2.lower()[:]

        #case 1:
        if str01 == str02:
            result = 0
        
        #case 2:
        elif abs(len(str01) - len(str02)) == 1:
            
            # Determining which is the big_str and small_str
            if len(str01) > len(str02):
                big_str = str01[:]
                small_str = str02[:]
                
            else:            
                big_str = str02[:]
                small_str = str01[:]
                
            #set result = 1 befor come in the for_loop.
            #Find only one difference character between big_str and small_str
            #then delete that difference character. Compare big_str with small_str,
            #if they are the same, return 1, else return 2.
            
            result = 1
            temp_str =''

            for pt in range(0, len(small_str)):

                if small_str[pt] != big_str[pt]:

                    temp_str = big_str.replace(big_str[pt], '', 1)[:]
                    big_str = temp_str[:]

                    if small_str != big_str:
                        result = 2
                        break

        #case 3        
        else:
            result = 2
            
        return result    


#main function------------------------------------------------------
    
    sentence_list = s1.split()
    correct_spell_list = s2[::]
    return_list01 = []
    return_list02 = []
    
    
#Filter 01----------------------------------------------------------
    for k in range(0, len(sentence_list)):
                            
        single_insert_or_delete_min = 3
        flag = -1
                            
        for l in range(0, len(correct_spell_list)):
                                
            if single_insert_or_delete(sentence_list[k], correct_spell_list[l]) < single_insert_or_delete_min:
                single_insert_or_delete_min = single_insert_or_delete(sentence_list[k], correct_spell_list[l])
                flag = l
                                    
        if  single_insert_or_delete_min == 1:
            return_list01.append(correct_spell_list[flag])
                                
        else:
            return_list01.append(sentence_list[k])    
    
                
#Filter 02------------------------------------------------------

    for i in range(0, len(return_list01)):
            
        find_mismatch_min = 3
        flag = -1
            
        for j in range(0, len(correct_spell_list)):
                
            if find_mismatch(return_list01[i], correct_spell_list[j]) < find_mismatch_min:
                find_mismatch_min = find_mismatch(return_list01[i], correct_spell_list[j])
                flag = j
                    
        if  find_mismatch_min == 1:
            return_list02.append(correct_spell_list[flag])
                
        else:
            return_list02.append(return_list01[i].lower())    
                
    
            
    #change form list to string
            
    return_str = ' '.join(map(str, return_list02))
                                                             
    return return_str

print(spelling_corrector('Thasts is the firs cas', ['that','first','case','car']))
#print(find_mismatch('Thes','that'))
#print(single_insert_or_delete('Wee', 'we'))





