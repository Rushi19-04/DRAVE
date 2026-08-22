import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { expect, test, vi } from 'vitest';
import { DeploymentModal } from './DeploymentModal';

test('Deployment button is disabled until exact detection ID is typed', async () => {
  const handleDeploy = vi.fn().mockResolvedValue({ status: 'success' });
  const handleClose = vi.fn();
  
  const ruleId = "11111111-1111-1111-1111-111111111111";
  
  render(
    <DeploymentModal 
      ruleId={ruleId}
      ruleName="Test Rule"
      onClose={handleClose}
      onDeploy={handleDeploy}
    />
  );
  
  const confirmInput = screen.getByTestId('confirmation-input');
  const deployButton = screen.getByTestId('deploy-button');
  
  // Initially disabled
  expect(deployButton).toBeDisabled();
  
  // Type wrong ID
  fireEvent.change(confirmInput, { target: { value: 'wrong-id' } });
  expect(deployButton).toBeDisabled();
  
  // Type correct ID
  fireEvent.change(confirmInput, { target: { value: ruleId } });
  expect(deployButton).not.toBeDisabled();
  
  // Click Deploy
  fireEvent.click(deployButton);
  
  expect(handleDeploy).toHaveBeenCalledWith(ruleId);
  expect(deployButton).toBeDisabled(); // Disabled while loading
});
