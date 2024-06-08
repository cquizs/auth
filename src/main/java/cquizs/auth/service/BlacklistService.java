package cquizs.auth.service;

import cquizs.auth.repository.BlacklistRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class BlacklistService {

    private final BlacklistRepository blacklistRepository;

    /**
     * 매 30분마다 만료된 토큰이 삭제된다.
     */
    @Scheduled(cron = "0 30 * * * *")
    @Transactional
    public void removeExpiredTokens(){
        LocalDateTime now = LocalDateTime.now();
        blacklistRepository.deleteAllByExpiryDateBefore(now);
        log.debug("만료 리프레시 토큰 삭제");
    }
}
